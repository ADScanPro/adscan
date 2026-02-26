"""AI service facade for ADscan CLI.

This module provides one stable entry point for conversational requests while
supporting two backend families:

- PydanticAI model providers (cloud/local API endpoints)
- Local CLI bridge backend (Codex/ChatGPT Plus-Pro wrapper)
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, TypedDict
from datetime import datetime, timezone
import importlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time

from adscan_internal import (
    print_error,
    print_error_debug,
    print_info_debug,
    print_warning,
    telemetry,
)
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.subprocess_env import get_clean_env_for_compilation
from adscan_internal.services.ai_context_builder import build_ai_system_prompt
from adscan_internal.services.ai_tools import AIAgentDependencies, register_ai_tools
from adscan_internal.services.llm.config import (
    AIConfig,
    apply_model_environment,
    load_ai_config,
)
from adscan_internal.services.llm.codex_app_server_client import (
    CodexAppServerClient,
    CodexAppServerError,
)
from adscan_internal.services.llm.external_cli_profiles import (
    get_external_cli_profile,
    normalize_external_cli_auth_check_command,
    normalize_external_cli_prompt_command_template,
)


class AIDependencyError(RuntimeError):
    """Raised when pydantic-ai is required but not available."""


class AIResponseMetadata(TypedDict, total=False):
    """Normalized metadata emitted for the last AI response."""

    provider: str
    backend: str
    model: str | None
    reasoning_effort: str | None
    status: str
    latency_ms: int
    usage_input_tokens: int
    usage_output_tokens: int
    usage_total_tokens: int
    usage_cost_usd: float
    usage_cost_source: str
    account_plan: str
    rate_limits: dict[str, Any]
    rate_limits_fetched_at_utc: str
    cli_action_command: str
    cli_action_status: str
    request_prompt_chars: int
    request_prompt_estimated_tokens: int
    note: str


@contextmanager
def _temporary_environment(env: dict[str, str]) -> Iterator[None]:
    """Temporarily apply environment overrides."""
    previous: dict[str, str | None] = {}
    try:
        for key, value in env.items():
            previous[key] = os.environ.get(key)
            os.environ[key] = value
        yield
    finally:
        for key, old in previous.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


class AIService:
    """Conversation and orchestration service for the `ask` command."""

    def __init__(
        self,
        *,
        shell: Any,
        policy_executor: Any,
        config: AIConfig | None = None,
    ) -> None:
        self._shell = shell
        self._policy_executor = policy_executor
        self._config = config or load_ai_config()
        self._agent: Any | None = None
        self._agent_cache_key: tuple[str, str] | None = None
        self._message_history: list[Any] = []
        self._codex_app_server_client: CodexAppServerClient | None = None
        self._last_response_metadata: AIResponseMetadata = {}
        self._executing_structured_cli_action = False

    @property
    def config(self) -> AIConfig:
        """Current AI configuration."""
        return self._config

    @property
    def last_response_metadata(self) -> AIResponseMetadata:
        """Metadata associated with the most recent ask response."""
        return dict(self._last_response_metadata)

    def refresh_config(self) -> None:
        """Reload persisted AI configuration."""
        if self._codex_app_server_client is not None:
            self._codex_app_server_client.close()
            self._codex_app_server_client = None
        self._config = load_ai_config()
        self._agent = None
        self._agent_cache_key = None

    def clear_history(self) -> None:
        """Clear conversation history."""
        self._message_history = []

    def get_runtime_snapshot(self) -> dict[str, Any]:
        """Return backend runtime metadata available without sending a prompt."""
        if self._config.uses_codex_app_server_backend():
            try:
                client = self._get_codex_app_server_client()
                return client.get_runtime_info(timeout_seconds=8)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                return {}
        return {}

    def ask_once(self, prompt: str, *, allow_cli_actions: bool = True) -> str:
        """Run one user request and return the text response."""
        ready, reason = self.validate_backend_ready()
        if not ready:
            self._last_response_metadata = {
                "provider": self._config.provider.value,
                "backend": self._config.backend_kind(),
                "status": "not_ready",
                "note": reason,
            }
            return reason

        if self._config.uses_codex_app_server_backend():
            return self._ask_via_codex_app_server(
                prompt,
                allow_cli_actions=allow_cli_actions,
            )

        if self._config.uses_external_cli_backend():
            return self._ask_via_cli_bridge(
                prompt,
                allow_cli_actions=allow_cli_actions,
            )

        agent = self._ensure_agent()
        deps = AIAgentDependencies(policy_executor=self._policy_executor)
        env = apply_model_environment(self._config)

        try:
            started = time.monotonic()
            prompt_chars = len(prompt)
            prompt_estimated_tokens = self._estimate_tokens(prompt)
            with _temporary_environment(env):
                result = agent.run_sync(
                    prompt,
                    deps=deps,
                    message_history=self._message_history,
                )
            latency_ms = max(1, int((time.monotonic() - started) * 1000))
            self._maybe_update_history(result)
            output = getattr(result, "output", result)
            usage = self._extract_usage_metadata(result)
            self._last_response_metadata = {
                "provider": self._config.provider.value,
                "backend": "pydantic_ai",
                "model": self._config.model,
                "status": "completed",
                "latency_ms": latency_ms,
                "request_prompt_chars": prompt_chars,
                "request_prompt_estimated_tokens": prompt_estimated_tokens,
                **usage,
            }
            text_output = self._coerce_output_to_text(output)
            if allow_cli_actions:
                return self._maybe_execute_cli_action_from_text(
                    text=text_output,
                    source_backend="pydantic_ai",
                )
            return text_output
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error_debug(f"AI ask failed: {type(exc).__name__}: {exc}")
            self._last_response_metadata = {
                "provider": self._config.provider.value,
                "backend": "pydantic_ai",
                "model": self._config.model,
                "status": "error",
                "note": str(exc),
            }
            return "AI request failed. Check model/provider configuration."

    def ask_stream(self, prompt: str) -> Iterator[str]:
        """Run one request and stream text chunks when supported."""
        ready, reason = self.validate_backend_ready()
        if not ready:
            yield reason
            return

        if self._config.uses_codex_app_server_backend():
            yield self._ask_via_codex_app_server(prompt)
            return

        if self._config.uses_external_cli_backend():
            # CLI bridge backends are currently request/response only.
            yield self._ask_via_cli_bridge(prompt)
            return

        agent = self._ensure_agent()
        deps = AIAgentDependencies(policy_executor=self._policy_executor)
        env = apply_model_environment(self._config)

        try:
            with _temporary_environment(env):
                with agent.run_stream_sync(
                    prompt,
                    deps=deps,
                    message_history=self._message_history,
                ) as result:
                    for chunk in result.stream_text():
                        yield chunk
                    self._maybe_update_history(result)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error_debug(f"AI stream failed: {type(exc).__name__}: {exc}")
            yield "AI streaming failed. Check model/provider configuration."

    def validate_backend_ready(self) -> tuple[bool, str]:
        """Validate backend configuration and runtime prerequisites."""
        if not self._config.enabled:
            return False, "AI is disabled in configuration."

        if self._config.uses_codex_app_server_backend():
            return self._validate_codex_app_server_backend()

        if self._config.uses_external_cli_backend():
            return self._validate_external_cli_backend()

        if self._config.requires_api_key() and not self._config.api_key.strip():
            return (
                False,
                "Selected provider requires an API key. Run `ask setup` to configure it.",
            )

        model_ref = self._config.resolved_model_ref()
        if not model_ref:
            return (
                False,
                "No model reference configured. Run `ask setup` to select provider/model.",
            )

        return True, "ok"

    def _ensure_agent(self) -> Any:
        """Create or reuse a cached PydanticAI agent instance."""
        model_ref = self._config.resolved_model_ref()
        if not model_ref:
            raise AIDependencyError(
                "No model reference configured for the selected AI provider."
            )

        cache_key = (self._config.provider.value, model_ref)
        if self._agent is not None and self._agent_cache_key == cache_key:
            return self._agent

        try:
            pydantic_ai_module = importlib.import_module("pydantic_ai")
            agent_cls = getattr(pydantic_ai_module, "Agent", None)
            if agent_cls is None:
                raise AIDependencyError(
                    "pydantic-ai Agent class is unavailable. Install dependencies and try again."
                )
        except Exception as exc:  # noqa: BLE001
            raise AIDependencyError(
                "pydantic-ai is not installed. Install dependencies and try again."
            ) from exc

        print_info_debug(f"Initializing AI agent with model_ref={model_ref}")
        self._agent = agent_cls(
            model=model_ref,
            system_prompt=build_ai_system_prompt(self._shell),
            deps_type=AIAgentDependencies,
        )
        register_ai_tools(self._agent)
        self._agent_cache_key = cache_key
        return self._agent

    def _ask_via_cli_bridge(
        self,
        prompt: str,
        *,
        allow_cli_actions: bool = True,
    ) -> str:
        """Run prompt through configured local CLI backend."""
        started = time.monotonic()
        template = self._resolve_prompt_command_template()
        if not template:
            provider = self._config.provider.value
            return f"Provider '{provider}' requires external_cli.command_template in AI setup."

        bridged_prompt = (
            self._build_action_contract_prompt(prompt)
            if allow_cli_actions
            else prompt
        )
        bridged_prompt_chars = len(bridged_prompt)
        bridged_prompt_estimated_tokens = self._estimate_tokens(bridged_prompt)
        argv = self._build_argv_from_prompt_template(
            template=template,
            prompt=bridged_prompt,
        )
        if not argv:
            return "External backend command template is invalid. Run `ask setup`."

        timeout = int(self._config.external_cli.timeout_seconds)
        cwd = self._config.external_cli.cwd.strip() or None
        print_info_debug(f"Running external AI CLI bridge command (argv): {argv}")
        proc = self._run_external_command(argv=argv, timeout=timeout, cwd=cwd)
        if proc is None:
            return "External CLI backend failed before returning output."

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            details = stderr or stdout or "No error details."
            print_warning("External CLI backend returned a non-zero exit code.")
            self._last_response_metadata = {
                "provider": self._config.provider.value,
                "backend": "exec_bridge",
                "model": self._config.model,
                "status": "error",
                "latency_ms": max(1, int((time.monotonic() - started) * 1000)),
                "request_prompt_chars": bridged_prompt_chars,
                "request_prompt_estimated_tokens": bridged_prompt_estimated_tokens,
                "note": details,
            }
            return f"External backend error: {details}"

        text = (proc.stdout or "").strip()
        if not text:
            self._last_response_metadata = {
                "provider": self._config.provider.value,
                "backend": "exec_bridge",
                "model": self._config.model,
                "status": "empty_output",
                "latency_ms": max(1, int((time.monotonic() - started) * 1000)),
                "request_prompt_chars": bridged_prompt_chars,
                "request_prompt_estimated_tokens": bridged_prompt_estimated_tokens,
            }
            return "External backend returned no output."
        self._last_response_metadata = {
            "provider": self._config.provider.value,
            "backend": "exec_bridge",
            "model": self._config.model,
            "status": "completed",
            "latency_ms": max(1, int((time.monotonic() - started) * 1000)),
            "request_prompt_chars": bridged_prompt_chars,
            "request_prompt_estimated_tokens": bridged_prompt_estimated_tokens,
        }
        if allow_cli_actions:
            return self._maybe_execute_cli_action_from_text(
                text=text,
                source_backend="exec_bridge",
            )
        return text

    def _ask_via_codex_app_server(
        self,
        prompt: str,
        *,
        allow_cli_actions: bool = True,
    ) -> str:
        """Run prompt through Codex app-server transport (Roo-style client flow)."""
        started = time.monotonic()
        timeout_seconds = int(self._config.external_cli.timeout_seconds)
        app_server_timeout_cap = int(
            os.getenv("ADSCAN_CODEX_APP_SERVER_TURN_TIMEOUT_CAP_SECONDS", "35")
        )
        app_server_timeout_seconds = min(timeout_seconds, max(10, app_server_timeout_cap))
        model = self._normalize_codex_model_for_app_server(self._config.model)
        print_info_debug(
            "Sending prompt via Codex app-server "
            f"(model={model}, timeout={app_server_timeout_seconds}s)."
        )
        try:
            client = self._get_codex_app_server_client()
            codex_prompt = (
                self._build_action_contract_prompt(prompt)
                if allow_cli_actions
                else prompt
            )
            codex_prompt_chars = len(codex_prompt)
            codex_prompt_estimated_tokens = self._estimate_tokens(codex_prompt)
            result = client.ask(
                prompt=codex_prompt,
                model=model,
                timeout_seconds=app_server_timeout_seconds,
            )
            runtime_info = client.get_runtime_info(timeout_seconds=8)
            latency_ms = max(1, int((time.monotonic() - started) * 1000))
            print_info_debug(
                "Codex app-server response received "
                f"(status={result.status}, chars={len(result.text)})."
            )
            metadata: AIResponseMetadata = {
                "provider": self._config.provider.value,
                "backend": "codex_app_server",
                "model": runtime_info.get("model") or model,
                "reasoning_effort": runtime_info.get("reasoning_effort"),
                "status": result.status,
                "latency_ms": latency_ms,
                "request_prompt_chars": codex_prompt_chars,
                "request_prompt_estimated_tokens": codex_prompt_estimated_tokens,
            }
            account_plan = runtime_info.get("account_plan")
            if isinstance(account_plan, str) and account_plan.strip():
                metadata["account_plan"] = account_plan.strip()
            rate_limits = runtime_info.get("rate_limits")
            if isinstance(rate_limits, dict):
                metadata["rate_limits"] = rate_limits
                metadata["rate_limits_fetched_at_utc"] = datetime.now(
                    timezone.utc
                ).isoformat()
            self._last_response_metadata = metadata
            if result.status == "partial_timeout":
                template = self._resolve_prompt_command_template()
                if template:
                    print_warning(
                        "Codex app-server did not emit a completion event in time; "
                        "falling back to legacy exec bridge."
                    )
                    self._last_response_metadata = {
                        **metadata,
                        "backend": "exec_bridge",
                        "note": "fallback_after_partial_timeout",
                    }
                    return self._ask_via_cli_bridge(
                        prompt,
                        allow_cli_actions=allow_cli_actions,
                    )
                if allow_cli_actions:
                    return self._maybe_execute_cli_action_from_text(
                        text=result.text,
                        source_backend="codex_app_server",
                    )
                return result.text
            if allow_cli_actions:
                return self._maybe_execute_cli_action_from_text(
                    text=result.text,
                    source_backend="codex_app_server",
                )
            return result.text
        except CodexAppServerError as exc:
            print_error_debug(f"Codex app-server ask failed: {exc}")
            diagnostics = self._collect_codex_runtime_diagnostics()
            if diagnostics:
                print_info_debug("Codex runtime diagnostics:\n" + "\n".join(diagnostics))
            if self._is_non_recoverable_codex_error(str(exc)):
                self._last_response_metadata = {
                    "provider": self._config.provider.value,
                    "backend": "codex_app_server",
                    "model": model,
                    "status": "error",
                    "latency_ms": max(1, int((time.monotonic() - started) * 1000)),
                    "note": str(exc),
                }
                return (
                    "Codex model/access error: the selected model is not available for "
                    "this account. Update model settings (Codex/OpenAI) and retry."
                )
            # Fallback path for environments where app-server transport is unavailable.
            template = self._resolve_prompt_command_template()
            if template:
                print_warning(
                    "Codex app-server unavailable; falling back to legacy exec bridge."
                )
                print_info_debug(f"Codex app-server fallback reason: {exc}")
                self._last_response_metadata = {
                    "provider": self._config.provider.value,
                    "backend": "codex_app_server",
                    "model": model,
                    "status": "error",
                    "latency_ms": max(1, int((time.monotonic() - started) * 1000)),
                    "note": str(exc),
                }
                return self._ask_via_cli_bridge(
                    prompt,
                    allow_cli_actions=allow_cli_actions,
                )
            self._last_response_metadata = {
                "provider": self._config.provider.value,
                "backend": "codex_app_server",
                "model": model,
                "status": "error",
                "latency_ms": max(1, int((time.monotonic() - started) * 1000)),
                "note": str(exc),
            }
            return f"Codex app-server error: {exc}"
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error_debug(f"Codex app-server unexpected failure: {exc}")
            self._last_response_metadata = {
                "provider": self._config.provider.value,
                "backend": "codex_app_server",
                "model": model,
                "status": "error",
                "latency_ms": max(1, int((time.monotonic() - started) * 1000)),
                "note": str(exc),
            }
            return "Codex app-server request failed."

    def _normalize_codex_model_for_app_server(self, configured_model: str) -> str | None:
        """Normalize model override for codex-cli app-server transport.

        Codex app-server is designed for Codex/OpenAI-backed model identifiers.
        If user configuration carries over a local API model id (for example
        `llama3.2:latest`), force provider default to avoid silent turn failures.
        """
        candidate = configured_model.strip()
        if not candidate:
            return None
        lowered = candidate.lower()
        if lowered in {"default", "auto", "codex"}:
            return None
        # Keep explicit OpenAI/Codex model ids.
        if lowered.startswith("gpt-"):
            return candidate
        if "codex" in lowered:
            return candidate

        print_warning(
            "Configured model is not Codex-compatible for subscription transport; "
            "using Codex provider default model."
        )
        return None

    def _validate_external_cli_backend(self) -> tuple[bool, str]:
        """Validate external CLI bridge configuration and auth preflight."""
        if not self._config.supports_subscription_cli_backend():
            provider = self._config.provider.value
            return (
                False,
                f"Provider '{provider}' is not supported in subscription CLI mode. "
                "Use API provider mode for this model family.",
            )

        template = self._resolve_prompt_command_template()
        if not template:
            return (
                False,
                "External CLI backend requires command template. Run `ask setup`.",
            )
        if "{prompt}" not in template:
            return (
                False,
                "External CLI command template must include `{prompt}` placeholder.",
            )

        argv = self._build_argv_from_prompt_template(
            template=template,
            prompt="healthcheck",
        )
        if not argv:
            return False, "Invalid external CLI command template."

        executable = argv[0]
        if not shutil.which(executable):
            return (
                False,
                f"CLI executable '{executable}' not found in PATH. Install it or update template.",
            )

        if not self._config.external_cli.preflight_enabled:
            return True, "ok"

        version_proc = self._run_external_command(
            argv=[executable, "--version"],
            timeout=min(10, int(self._config.external_cli.timeout_seconds)),
            cwd=self._config.external_cli.cwd.strip() or None,
        )
        if version_proc is not None and version_proc.returncode != 0:
            print_info_debug(
                f"External CLI version preflight returned exit code {version_proc.returncode}."
            )

        auth_check_command = self._resolve_auth_check_command(executable=executable)
        if auth_check_command:
            auth_argv = self._build_argv_from_static_template(auth_check_command)
            if not auth_argv:
                return (
                    False,
                    "Invalid external CLI auth check command in configuration.",
                )
            auth_proc = self._run_external_command(
                argv=auth_argv,
                timeout=min(20, int(self._config.external_cli.timeout_seconds)),
                cwd=self._config.external_cli.cwd.strip() or None,
            )
            if auth_proc is None:
                return False, "External CLI auth check failed before returning output."
            if auth_proc.returncode != 0:
                stderr = (auth_proc.stderr or "").lower()
                stdout = (auth_proc.stdout or "").lower()
                combined = f"{stdout}\n{stderr}"
                if self._looks_like_unsupported_auth_command(combined):
                    print_info_debug(
                        "External CLI auth check command appears unsupported; "
                        "continuing without strict auth verification."
                    )
                    return True, "ok"
                hint = self._build_login_hint()
                return (
                    False,
                    f"External CLI appears unauthenticated or unavailable. {hint}",
                )

        return True, "ok"

    def _validate_codex_app_server_backend(self) -> tuple[bool, str]:
        """Validate Codex app-server prerequisites."""
        executable = "codex"
        if not shutil.which(executable):
            return (
                False,
                "Codex CLI is not installed or not in PATH.",
            )

        if not self._config.external_cli.preflight_enabled:
            return True, "ok"

        auth_cmd = normalize_external_cli_auth_check_command(
            self._config.provider,
            self._config.external_cli.auth_check_command.strip()
            or "codex login status",
        )
        auth_argv = self._build_argv_from_static_template(auth_cmd)
        if not auth_argv:
            return False, "Invalid Codex auth check command in configuration."
        auth_proc = self._run_external_command(
            argv=auth_argv,
            timeout=min(20, int(self._config.external_cli.timeout_seconds)),
            cwd=self._config.external_cli.cwd.strip() or None,
        )
        if auth_proc is None:
            return False, "Codex auth check failed before returning output."
        if auth_proc.returncode != 0:
            hint = self._build_login_hint()
            return (
                False,
                f"Codex appears unauthenticated or unavailable. {hint}",
            )

        return True, "ok"

    def _get_codex_app_server_client(self) -> CodexAppServerClient:
        """Create or reuse the persistent Codex app-server client."""
        if self._codex_app_server_client is not None:
            return self._codex_app_server_client

        cwd = self._config.external_cli.cwd.strip() or None
        command = self._build_codex_app_server_command()
        command_env = self._build_external_cli_subprocess_env()
        print_info_debug(f"Initializing Codex app-server transport with command: {command}")
        self._codex_app_server_client = CodexAppServerClient(
            command=command,
            startup_timeout_seconds=15,
            turn_timeout_seconds=int(self._config.external_cli.timeout_seconds),
            cwd=cwd,
            env=command_env,
            trace=lambda message: print_info_debug(f"[codex-app] {message}"),
        )
        return self._codex_app_server_client

    @staticmethod
    def _build_codex_app_server_command() -> list[str]:
        """Build codex app-server command with safe defaults for ADscan runtime."""
        allow_mcp = os.getenv("ADSCAN_CODEX_APP_SERVER_ALLOW_MCP", "").strip().lower()
        if allow_mcp in {"1", "true", "yes", "on"}:
            return ["codex", "app-server"]
        # By default disable user/global Codex MCP server startup.
        # This avoids unrelated MCP config drift causing startup hangs in ADscan.
        return ["codex", "app-server", "-c", "mcp_servers={}"]

    def _collect_codex_runtime_diagnostics(self) -> list[str]:
        """Collect best-effort diagnostics when Codex app-server fails."""
        lines: list[str] = []
        cwd = self._config.external_cli.cwd.strip() or None
        command = self._build_codex_app_server_command()
        lines.append(f"app-server command={command}")

        version_proc = self._run_external_command(
            argv=["codex", "--version"],
            timeout=10,
            cwd=cwd,
        )
        if version_proc is None:
            lines.append("codex --version: failed to execute")
        elif version_proc.returncode != 0:
            details = (version_proc.stderr or version_proc.stdout or "").strip()
            lines.append(f"codex --version: exit={version_proc.returncode} details={details}")
        else:
            lines.append(f"codex --version: {(version_proc.stdout or '').strip()}")

        auth_cmd = normalize_external_cli_auth_check_command(
            self._config.provider,
            self._config.external_cli.auth_check_command.strip() or "codex login status",
        )
        auth_argv = self._build_argv_from_static_template(auth_cmd)
        if auth_argv:
            auth_proc = self._run_external_command(
                argv=auth_argv,
                timeout=15,
                cwd=cwd,
            )
            if auth_proc is None:
                lines.append(f"{auth_cmd}: failed to execute")
            else:
                details = (auth_proc.stderr or auth_proc.stdout or "").strip()
                lines.append(
                    f"{auth_cmd}: exit={auth_proc.returncode} details={details[:240]}"
                )
        return lines

    @staticmethod
    def _is_non_recoverable_codex_error(details: str) -> bool:
        """Return whether Codex error should fail fast without exec fallback."""
        lowered = details.lower()
        markers = (
            "does not exist",
            "do not have access",
            "invalid model",
            "not available for your account",
            "forbidden",
            "unauthorized",
        )
        return any(marker in lowered for marker in markers)

    def _resolve_auth_check_command(self, *, executable: str) -> str:
        """Return auth check command configured for external CLI provider."""
        configured = self._config.external_cli.auth_check_command.strip()
        if configured:
            return normalize_external_cli_auth_check_command(
                self._config.provider,
                configured,
            )

        profile = get_external_cli_profile(self._config.provider)
        if profile and profile.default_auth_check_command.strip():
            if profile.binary_name == executable:
                return normalize_external_cli_auth_check_command(
                    self._config.provider,
                    profile.default_auth_check_command,
                )
        return ""

    def _resolve_prompt_command_template(self) -> str:
        """Resolve effective prompt command template for external CLI backend."""
        configured = self._config.external_cli.command_template.strip()
        if "{prompt}" in configured:
            return normalize_external_cli_prompt_command_template(
                self._config.provider,
                configured,
            )

        profile = get_external_cli_profile(self._config.provider)
        if profile is None:
            return configured
        default_template = profile.default_prompt_command_template.strip()
        if "{prompt}" in default_template:
            return normalize_external_cli_prompt_command_template(
                self._config.provider,
                default_template,
            )
        return configured

    def _build_login_hint(self) -> str:
        """Build actionable login hint for external CLI backends."""
        profile = get_external_cli_profile(self._config.provider)
        if profile is None:
            return "Login to the CLI backend and retry."
        return f"{profile.login_hint} See: {profile.docs_url}"

    @staticmethod
    def _build_argv_from_prompt_template(*, template: str, prompt: str) -> list[str]:
        """Build argv from prompt template without shell execution."""
        if "{prompt}" not in template:
            return []
        placeholder = "__ADSCAN_PROMPT_PLACEHOLDER__"
        raw = template.replace("{prompt}", placeholder)
        try:
            tokens = shlex.split(raw)
        except ValueError:
            return []

        argv = [token.replace(placeholder, prompt) for token in tokens]
        return [token for token in argv if token]

    @staticmethod
    def _build_argv_from_static_template(template: str) -> list[str]:
        """Build argv from command template without prompt substitution."""
        try:
            tokens = shlex.split(template)
        except ValueError:
            return []
        return [token for token in tokens if token]

    def _run_external_command(
        self,
        *,
        argv: list[str],
        timeout: int,
        cwd: str | None,
    ) -> subprocess.CompletedProcess[str] | None:
        """Execute external backend command without shell invocation."""
        if not argv:
            return None

        runner = getattr(self._shell, "command_runner", None) or default_runner
        command_env = self._build_external_cli_subprocess_env()
        try:
            return runner.run(
                CommandSpec(
                    command=argv,
                    timeout=timeout,
                    shell=False,
                    capture_output=True,
                    text=True,
                    check=False,
                    cwd=cwd,
                    env=command_env,
                )
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error_debug(
                f"External CLI backend command failed: {type(exc).__name__}: {exc}"
            )
            return None

    @staticmethod
    def _build_external_cli_subprocess_env() -> dict[str, str] | None:
        """Build a safe subprocess environment for external CLI backends.

        In PyInstaller-frozen builds, avoid inherited bundled libs causing
        host binary incompatibilities (e.g. node/codex GLIBCXX mismatches).
        """
        if not getattr(sys, "frozen", False):
            return None
        return get_clean_env_for_compilation()

    @staticmethod
    def _looks_like_unsupported_auth_command(output: str) -> bool:
        """Best-effort detection of unsupported auth-check subcommands."""
        markers = (
            "unknown command",
            "unrecognized",
            "no such command",
            "invalid choice",
            "did you mean",
        )
        return any(marker in output for marker in markers)

    @staticmethod
    def _coerce_output_to_text(output: Any) -> str:
        """Convert structured outputs into compact text."""
        if isinstance(output, str):
            return output
        try:
            return json.dumps(output, ensure_ascii=False, indent=2, default=str)
        except Exception:
            return str(output)

    def _build_action_contract_prompt(self, prompt: str) -> str:
        """Wrap user prompt with a backend-agnostic CLI action contract."""
        catalog_lines = self._build_cli_catalog_lines(prompt=prompt)
        catalog_block = "\n".join(catalog_lines) if catalog_lines else "- (no catalog available)"
        return (
            "ADscan execution contract:\n"
            "- You may request execution ONLY via JSON object with this exact shape:\n"
            '{"adscan_action":{"command":"<cli_command>","arguments":"<args>","reason":"<why>"}}\n'
            "- command MUST be one ADscan CLI command (without do_ prefix).\n"
            "- Never use system command.\n"
            "- Do not use file-navigation/file-view commands (cat/ls/cp/mv/rm/mkdir) unless "
            "the user explicitly asks for filesystem operations.\n"
            "- If user asks about discovered credentials, prefer command `creds` with "
            "arguments `show`.\n"
            "- If the user request is informational and should not execute a CLI command, respond normally.\n"
            "- Relevant command catalog for this prompt:\n"
            f"{catalog_block}\n\n"
            f"User request:\n{prompt}"
        )

    def _build_cli_catalog_lines(self, *, prompt: str) -> list[str]:
        """Build ranked command catalog lines for current prompt."""
        lines: list[str] = []
        total_allowlist = 0
        try:
            total_allowlist = len(self._policy_executor.list_allowed_cli_commands())
        except Exception:  # noqa: BLE001
            total_allowlist = 0
        max_entries = total_allowlist if total_allowlist > 0 else self._resolve_catalog_max_entries()
        try:
            catalog = self._policy_executor.get_cli_command_catalog(
                prompt=prompt,
                max_entries=max_entries,
            )
        except Exception:  # noqa: BLE001
            catalog = []
        for command, description in catalog:
            if description:
                lines.append(f"- {command}: {description}")
            else:
                lines.append(f"- {command}")
        print_info_debug(
            "AI CLI command catalog stats: "
            f"total_allowlist={total_allowlist} sent_to_model={len(lines)} "
            f"max_entries={max_entries}"
        )
        if lines:
            preview = "\n".join(lines[:10])
            print_info_debug(
                "AI CLI command catalog preview for prompt:\n"
                f"{preview}"
            )
        else:
            print_info_debug("AI CLI command catalog preview for prompt: <empty>")
        return lines

    @staticmethod
    def _resolve_catalog_max_entries() -> int:
        """Resolve max command catalog size sent to the model."""
        raw = os.getenv("ADSCAN_AI_COMMAND_CATALOG_MAX_ENTRIES", "20").strip()
        try:
            value = int(raw)
        except ValueError:
            return 20
        return max(5, min(value, 120))

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Estimate token count with a conservative chars-per-token heuristic."""
        if not text:
            return 0
        return max(1, int(len(text) / 4))

    def _maybe_execute_cli_action_from_text(
        self,
        *,
        text: str,
        source_backend: str,
    ) -> str:
        """Execute CLI action when model returns a valid adscan_action payload."""
        if self._executing_structured_cli_action:
            print_warning(
                "Skipping nested AI CLI action execution to prevent recursion."
            )
            return text

        action = self._extract_cli_action_payload(text)
        if action is None:
            return text

        command = action.get("command", "").strip()
        arguments = action.get("arguments", "")
        reason = action.get("reason", "")
        if not command:
            return text

        print_info_debug(
            "AI returned structured CLI action request: "
            f"backend={source_backend} command={command} "
            f"arguments={arguments!r} reason={reason!r}"
        )
        if not reason.strip():
            print_warning(
                "AI selected a CLI command without an explicit reason. "
                "Proceed with extra caution when confirming."
            )
        self._executing_structured_cli_action = True
        try:
            result = self._policy_executor.dispatch_cli_command(
                command=command,
                arguments=arguments,
                reason=reason,
            )
        finally:
            self._executing_structured_cli_action = False
        self._last_response_metadata = {
            **self._last_response_metadata,
            "cli_action_command": command,
            "cli_action_status": result.split(":", 1)[0].strip(),
        }
        return f"CLI action result: {result}"

    @staticmethod
    def _extract_cli_action_payload(text: str) -> dict[str, str] | None:
        """Extract `adscan_action` dict from plain/markdown JSON output."""
        payload = text.strip()
        if not payload:
            return None

        candidates = [payload]
        if "```" in payload:
            for block in payload.split("```"):
                block_clean = block.strip()
                if not block_clean:
                    continue
                if block_clean.startswith("json"):
                    block_clean = block_clean[4:].strip()
                candidates.append(block_clean)

        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict):
                continue
            action = parsed.get("adscan_action")
            if not isinstance(action, dict):
                continue
            command = action.get("command")
            arguments = action.get("arguments", "")
            reason = action.get("reason", "")
            if not isinstance(command, str):
                continue
            if not isinstance(arguments, str):
                arguments = ""
            if not isinstance(reason, str):
                reason = ""
            return {
                "command": command,
                "arguments": arguments,
                "reason": reason,
            }
        return None

    def _maybe_update_history(self, result: Any) -> None:
        """Persist message history if backend result exposes it."""
        try:
            if hasattr(result, "all_messages"):
                self._message_history = list(result.all_messages())
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Failed to persist AI conversation history.")

    @staticmethod
    def _extract_usage_metadata(result: Any) -> dict[str, Any]:
        """Extract best-effort token/cost usage metadata from pydantic-ai result."""
        usage_obj = None
        usage_attr = getattr(result, "usage", None)
        if callable(usage_attr):
            try:
                usage_obj = usage_attr()
            except Exception:  # noqa: BLE001
                usage_obj = None
        elif usage_attr is not None:
            usage_obj = usage_attr

        if usage_obj is None:
            return {}

        payload: dict[str, Any]
        if isinstance(usage_obj, dict):
            payload = usage_obj
        elif hasattr(usage_obj, "model_dump"):
            try:
                payload = usage_obj.model_dump()  # type: ignore[assignment]
            except Exception:  # noqa: BLE001
                payload = {}
        elif hasattr(usage_obj, "__dict__"):
            payload = dict(vars(usage_obj))
        else:
            payload = {}

        def _first_int(*keys: str) -> int | None:
            for key in keys:
                value = payload.get(key)
                if isinstance(value, int):
                    return value
            return None

        def _first_float(*keys: str) -> float | None:
            for key in keys:
                value = payload.get(key)
                if isinstance(value, (int, float)):
                    return float(value)
            return None

        input_tokens = _first_int("input_tokens", "request_tokens", "prompt_tokens")
        output_tokens = _first_int(
            "output_tokens",
            "response_tokens",
            "completion_tokens",
        )
        total_tokens = _first_int("total_tokens")
        if total_tokens is None and (
            isinstance(input_tokens, int) or isinstance(output_tokens, int)
        ):
            total_tokens = (input_tokens or 0) + (output_tokens or 0)
        usage_meta: dict[str, Any] = {}
        if isinstance(input_tokens, int):
            usage_meta["usage_input_tokens"] = input_tokens
        if isinstance(output_tokens, int):
            usage_meta["usage_output_tokens"] = output_tokens
        if isinstance(total_tokens, int):
            usage_meta["usage_total_tokens"] = total_tokens

        cost_usd = _first_float("cost", "cost_usd", "total_cost")
        if cost_usd is not None:
            usage_meta["usage_cost_usd"] = round(cost_usd, 6)
            usage_meta["usage_cost_source"] = "provider_response"
        return usage_meta
