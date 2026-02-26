"""PydanticAI tool registry for ADscan CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AIAgentDependencies:
    """Dependencies injected into PydanticAI tool context."""

    policy_executor: Any


def register_ai_tools(agent: Any) -> None:
    """Register ADscan tools into a PydanticAI agent instance."""
    @agent.tool  # type: ignore[attr-defined]
    def list_cli_commands(ctx: Any) -> str:
        """List allowed ADscan CLI commands available to the AI agent."""
        commands = ctx.deps.policy_executor.list_allowed_cli_commands()
        return "\n".join(commands)

    @agent.tool  # type: ignore[attr-defined]
    def run_cli_command(
        ctx: Any,
        command: str,
        arguments: str = "",
        reason: str = "",
    ) -> str:
        """Execute one allowlisted ADscan CLI command (never `system`)."""
        return ctx.deps.policy_executor.dispatch_cli_command(
            command=command,
            arguments=arguments,
            reason=reason,
        )

    @agent.tool  # type: ignore[attr-defined]
    def run_domain_action(
        ctx: Any,
        action: str,
        domain: str = "",
        arguments: str = "",
        reason: str = "",
    ) -> str:
        """Dispatch one legacy mapped action through centralized policy executor."""
        return ctx.deps.policy_executor.dispatch_domain_action(
            action=action,
            domain=domain or None,
            arguments=arguments,
            reason=reason,
        )
