"""Helpers to evaluate whether AI backends are configured for share analysis."""

from __future__ import annotations

from dataclasses import dataclass

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.llm.config import AIConfig, AIProvider, get_ai_config_path, load_ai_config


@dataclass(frozen=True)
class AIBackendAvailability:
    """Normalized AI backend availability state for interactive UX decisions."""

    configured: bool
    enabled: bool
    provider: str
    reason: str


class AIBackendAvailabilityService(BaseService):
    """Resolve whether AI is configured enough to expose AI-driven workflows."""

    def get_availability(
        self,
        *,
        config: AIConfig | None = None,
        config_path_exists: bool | None = None,
    ) -> AIBackendAvailability:
        """Return AI backend availability for optional UX branching.

        Args:
            config: Optional preloaded AI configuration.
            config_path_exists: Optional override for persisted-config presence.

        Returns:
            ``AIBackendAvailability`` describing whether AI should be offered.
        """
        resolved_config = config or load_ai_config()
        provider = resolved_config.provider.value
        persisted = (
            bool(config_path_exists)
            if config_path_exists is not None
            else get_ai_config_path().exists()
        )

        if not resolved_config.enabled:
            return AIBackendAvailability(
                configured=False,
                enabled=False,
                provider=provider,
                reason="ai_disabled",
            )

        if not persisted:
            return AIBackendAvailability(
                configured=False,
                enabled=True,
                provider=provider,
                reason="no_persisted_ai_config",
            )

        if resolved_config.provider == AIProvider.CODEX_CLI:
            return AIBackendAvailability(
                configured=True,
                enabled=True,
                provider=provider,
                reason="codex_cli_configured",
            )

        if resolved_config.requires_api_key():
            has_api_key = bool(resolved_config.api_key.strip())
            return AIBackendAvailability(
                configured=has_api_key,
                enabled=True,
                provider=provider,
                reason="api_key_configured" if has_api_key else "api_key_missing",
            )

        if resolved_config.provider in {AIProvider.OLLAMA, AIProvider.OPENAI_COMPATIBLE}:
            return AIBackendAvailability(
                configured=True,
                enabled=True,
                provider=provider,
                reason="local_or_openai_compatible_configured",
            )

        return AIBackendAvailability(
            configured=False,
            enabled=True,
            provider=provider,
            reason="provider_not_supported_for_selector",
        )
