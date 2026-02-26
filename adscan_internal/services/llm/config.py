"""Persistent AI configuration for ADscan CLI and service layers."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any
import json
import os
from pydantic import BaseModel, Field

from adscan_core.paths import get_state_dir


class AIProvider(str, Enum):
    """Supported AI backends for ADscan."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    OPENAI_COMPATIBLE = "openai_compatible"
    CODEX_CLI = "codex_cli"
    # Kept for backward compatibility with existing persisted configs.
    # Subscription CLI mode for these providers is intentionally disabled.
    GEMINI_CLI = "gemini_cli"
    CLAUDE_CODE_CLI = "claude_code_cli"


class CodexTransport(str, Enum):
    """Transport modes for Codex subscription integration."""

    APP_SERVER = "app_server"
    EXEC_BRIDGE = "exec_bridge"


class AIPrivacyMode(str, Enum):
    """Data handling modes for prompts and context payloads."""

    LOCAL_ONLY = "local_only"
    CLOUD_ALLOWED = "cloud_allowed"
    CLOUD_REDACTED = "cloud_redacted"


class ExternalCliBackendConfig(BaseModel):
    """Configuration for local CLI-model bridge backends.

    `command_template` must include `{prompt}` placeholder.
    """

    command_template: str = ""
    auth_check_command: str = ""
    timeout_seconds: int = Field(default=180, ge=5, le=3600)
    cwd: str = ""
    preflight_enabled: bool = True


class AIAskConfig(BaseModel):
    """Configuration for the interactive `ask` workflow."""

    streaming: bool = True
    max_tool_calls_per_turn: int = Field(default=10, ge=1, le=100)
    max_output_file_size_mb: int = Field(default=5, ge=1, le=100)
    session_timeout_minutes: int = Field(default=30, ge=1, le=1440)


class AIConfig(BaseModel):
    """Top-level AI configuration model."""

    enabled: bool = True
    provider: AIProvider = AIProvider.OLLAMA
    model: str = "llama3.2:latest"
    model_ref: str = ""
    api_key: str = ""
    base_url: str = ""
    privacy_mode: AIPrivacyMode = AIPrivacyMode.LOCAL_ONLY
    codex_transport: CodexTransport = CodexTransport.APP_SERVER
    natural_language_mode: bool = False
    ask: AIAskConfig = Field(default_factory=AIAskConfig)
    external_cli: ExternalCliBackendConfig = Field(
        default_factory=ExternalCliBackendConfig
    )

    def resolved_model_ref(self) -> str:
        """Return the effective PydanticAI model identifier."""
        if self.model_ref.strip():
            return self.model_ref.strip()

        if self.provider == AIProvider.OPENAI:
            return f"openai:{self.model}"
        if self.provider == AIProvider.ANTHROPIC:
            return f"anthropic:{self.model}"
        if self.provider == AIProvider.GEMINI:
            # google-gla provider uses Gemini API key in environment.
            return f"google-gla:{self.model}"
        if self.provider == AIProvider.OLLAMA:
            # Uses OpenAI-compatible endpoint exposed by Ollama.
            return f"openai:{self.model}"
        if self.provider == AIProvider.OPENAI_COMPATIBLE:
            return f"openai:{self.model}"
        return ""

    def uses_external_cli_backend(self) -> bool:
        """Return whether the current provider is bridged via local CLI."""
        return self.provider in {
            AIProvider.CODEX_CLI,
            AIProvider.GEMINI_CLI,
            AIProvider.CLAUDE_CODE_CLI,
        }

    def uses_codex_app_server_backend(self) -> bool:
        """Return whether Codex should run via app-server JSON-RPC transport."""
        return (
            self.provider == AIProvider.CODEX_CLI
            and self.codex_transport == CodexTransport.APP_SERVER
        )

    def supports_subscription_cli_backend(self) -> bool:
        """Return whether provider is currently supported in subscription CLI mode."""
        return self.provider == AIProvider.CODEX_CLI

    def uses_api_provider_backend(self) -> bool:
        """Return whether provider uses direct API model access."""
        return not self.uses_external_cli_backend()

    def requires_api_key(self) -> bool:
        """Return whether the selected provider requires API key by default."""
        return self.provider in {
            AIProvider.OPENAI,
            AIProvider.ANTHROPIC,
            AIProvider.GEMINI,
        }

    def backend_kind(self) -> str:
        """Return normalized backend family identifier."""
        return "external_cli" if self.uses_external_cli_backend() else "api_provider"


def get_ai_config_path() -> Path:
    """Return the persistent AI config path in ADscan state directory."""
    return get_state_dir() / "ai_config.json"


def load_ai_config() -> AIConfig:
    """Load AI config from disk or return defaults."""
    path = get_ai_config_path()
    if not path.exists():
        return AIConfig()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return AIConfig()
        return AIConfig.model_validate(payload)
    except Exception:
        return AIConfig()


def save_ai_config(config: AIConfig) -> Path:
    """Persist AI config to disk and return the written path."""
    path = get_ai_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config.model_dump(mode="json"), handle, indent=2, sort_keys=True)
    return path


def apply_model_environment(config: AIConfig) -> dict[str, str]:
    """Build environment variables required by the selected model backend.

    Returns a copy of the process environment with provider-specific keys set.
    """
    env = dict(os.environ)
    if config.provider == AIProvider.OPENAI and config.api_key:
        env["OPENAI_API_KEY"] = config.api_key
    elif config.provider == AIProvider.ANTHROPIC and config.api_key:
        env["ANTHROPIC_API_KEY"] = config.api_key
    elif config.provider == AIProvider.GEMINI and config.api_key:
        env["GEMINI_API_KEY"] = config.api_key
    elif config.provider in {AIProvider.OLLAMA, AIProvider.OPENAI_COMPATIBLE}:
        # OpenAI-compatible endpoints generally require an API key value even for
        # local backends; "ollama" is accepted by Ollama-compatible servers.
        env["OPENAI_API_KEY"] = config.api_key or "ollama"
        if config.provider == AIProvider.OLLAMA:
            env["OPENAI_BASE_URL"] = (
                config.base_url.strip() or "http://localhost:11434/v1"
            )
        else:
            env["OPENAI_BASE_URL"] = (
                config.base_url.strip() or "http://localhost:4000/v1"
            )
    return env


def masked_status(config: AIConfig) -> dict[str, Any]:
    """Return safe config data suitable for CLI status rendering."""
    key = config.api_key
    if key:
        masked = f"{key[:4]}...{key[-4:]}" if len(key) >= 8 else "***"
    else:
        masked = ""
    uses_codex_subscription = config.provider == AIProvider.CODEX_CLI
    return {
        "enabled": config.enabled,
        "provider": config.provider.value,
        "codex_transport": config.codex_transport.value,
        "backend_kind": config.backend_kind(),
        "model": config.model,
        "model_ref": config.resolved_model_ref(),
        "privacy_mode": config.privacy_mode.value,
        "natural_language_mode": config.natural_language_mode,
        "streaming": config.ask.streaming,
        "api_key_masked": masked,
        "base_url": config.base_url,
        "external_cli_configured": bool(config.external_cli.command_template.strip())
        or uses_codex_subscription,
        "external_cli_preflight_enabled": config.external_cli.preflight_enabled,
        "external_cli_auth_check_configured": bool(
            config.external_cli.auth_check_command.strip()
        )
        or uses_codex_subscription,
    }
