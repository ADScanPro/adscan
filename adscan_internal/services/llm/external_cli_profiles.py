"""Provider profiles for subscription-oriented local CLI backends."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
import shlex

from adscan_internal.services.llm.config import AIProvider


@dataclass(frozen=True)
class ExternalCliProviderProfile:
    """Static behavior metadata for one external CLI provider."""

    provider: AIProvider
    display_name: str
    binary_name: str
    default_prompt_command_template: str
    default_auth_check_command: str
    default_login_command: str
    default_logout_command: str
    login_hint: str
    docs_url: str


_EXTERNAL_CLI_PROFILES: Mapping[AIProvider, ExternalCliProviderProfile] = {
    AIProvider.CODEX_CLI: ExternalCliProviderProfile(
        provider=AIProvider.CODEX_CLI,
        display_name="OpenAI Codex CLI (ChatGPT Plus/Pro compatible)",
        binary_name="codex",
        default_prompt_command_template="codex exec --skip-git-repo-check {prompt}",
        default_auth_check_command="codex login status",
        default_login_command="codex login",
        default_logout_command="codex logout",
        login_hint="Run `codex login` and complete sign-in before using `ask`.",
        docs_url="https://help.openai.com/en/articles/11381614",
    ),
}


def get_external_cli_profile(provider: AIProvider) -> ExternalCliProviderProfile | None:
    """Return provider profile for CLI-based backends."""
    return _EXTERNAL_CLI_PROFILES.get(provider)


def list_external_cli_profiles() -> list[ExternalCliProviderProfile]:
    """Return all known local CLI provider profiles."""
    return list(_EXTERNAL_CLI_PROFILES.values())


def normalize_external_cli_auth_check_command(
    provider: AIProvider,
    command: str,
) -> str:
    """Normalize persisted auth-check commands for known backward-compat cases."""
    normalized = command.strip()
    if not normalized:
        return normalized

    if provider == AIProvider.CODEX_CLI and normalized == "codex auth status":
        return "codex login status"

    return normalized


def normalize_external_cli_prompt_command_template(
    provider: AIProvider,
    template: str,
) -> str:
    """Normalize persisted prompt command templates for backward compatibility."""
    normalized = template.strip()
    if not normalized:
        return normalized

    if provider != AIProvider.CODEX_CLI:
        return normalized

    try:
        tokens = shlex.split(normalized)
    except ValueError:
        return normalized

    if len(tokens) >= 2 and tokens[0] == "codex" and tokens[1] == "exec":
        if "--skip-git-repo-check" not in tokens:
            tokens.insert(2, "--skip-git-repo-check")
        return shlex.join(tokens)

    return normalized
