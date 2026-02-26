"""CLI handlers for AI assistant features (`ask` command)."""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone
from pathlib import Path
import json
import shlex
import shutil
import subprocess
import sys
import tempfile

from rich.prompt import Confirm, Prompt
from rich.table import Table

from adscan_internal import (
    print_error,
    print_error_debug,
    print_info,
    print_info_debug,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.rich_output import mark_sensitive, print_panel, print_table
from adscan_internal.subprocess_env import get_clean_env_for_compilation
from adscan_internal.services.llm.config import (
    AIPrivacyMode,
    AIProvider,
    CodexTransport,
    load_ai_config,
    masked_status,
    save_ai_config,
)
from adscan_internal.services.llm.external_cli_profiles import (
    get_external_cli_profile,
    list_external_cli_profiles,
    normalize_external_cli_auth_check_command,
)
from adscan_core.paths import get_state_dir

SETUP_PROVIDER_CHOICES: tuple[AIProvider, ...] = (
    AIProvider.OPENAI,
    AIProvider.ANTHROPIC,
    AIProvider.GEMINI,
    AIProvider.OLLAMA,
    AIProvider.OPENAI_COMPATIBLE,
    AIProvider.CODEX_CLI,
)


def handle_ask_command(shell: Any, args: str) -> None:
    """Handle the `ask` command entry point.

    Supported usage:
    - `ask help`
    - `ask setup`
    - `ask status`
    - `ask usage [day|week|all]`
    - `ask usage budget <show|daily <usd>|weekly <usd>|clear>`
    - `ask doctor`
    - `ask codex-schema`
    - `ask login [codex]`
    - `ask logout [codex]`
    - `ask auth-status [codex]`
    - `ask clear`
    - `ask <prompt>`
    - `ask` (interactive loop)
    """
    arg_line = (args or "").strip()
    if not arg_line:
        _run_interactive_ask(shell)
        return

    argv = shlex.split(arg_line)
    subcommand = argv[0].lower()
    if subcommand in {"help", "--help", "-h"}:
        run_ask_help()
        return
    if subcommand == "setup":
        run_ask_setup(shell)
        return
    if subcommand == "status":
        run_ask_status(shell)
        return
    if subcommand == "usage":
        run_ask_usage(shell, argv[1:])
        return
    if subcommand == "doctor":
        run_ask_doctor(shell)
        return
    if subcommand in {"codex-schema", "codex_schema"}:
        run_ask_codex_schema(shell)
        return
    if subcommand == "schema" and len(argv) > 1 and argv[1].lower() == "codex":
        run_ask_codex_schema(shell)
        return
    if subcommand == "login":
        backend = argv[1].lower() if len(argv) > 1 else "codex"
        run_ask_login(shell, backend=backend)
        return
    if subcommand == "logout":
        backend = argv[1].lower() if len(argv) > 1 else "codex"
        run_ask_logout(shell, backend=backend)
        return
    if subcommand in {"auth-status", "auth_status"}:
        backend = argv[1].lower() if len(argv) > 1 else "codex"
        run_ask_auth_status(shell, backend=backend)
        return
    if subcommand == "clear":
        service = shell._get_ai_service()
        if service is None:
            return
        service.clear_history()
        print_success("AI conversation history cleared.")
        return

    prompt = arg_line
    _run_single_prompt(shell, prompt)


def run_ask_setup(shell: Any) -> None:
    """Interactive wizard for AI backend configuration."""
    config = load_ai_config()
    _print_provider_overview()
    default_provider = (
        config.provider
        if config.provider in SETUP_PROVIDER_CHOICES
        else AIProvider.OLLAMA
    )
    provider_options = [provider.value for provider in SETUP_PROVIDER_CHOICES]
    try:
        default_provider_idx = provider_options.index(default_provider.value)
    except ValueError:
        default_provider_idx = 0
    provider_choice = _select_option(
        shell=shell,
        title="Select AI provider/backend:",
        options=provider_options,
        default_idx=default_provider_idx,
    )
    if provider_choice is None:
        print_warning("Setup cancelled by user.")
        return
    provider = AIProvider(provider_choice)
    model_default = _default_model_for_provider(provider)
    model_value = Prompt.ask(
        "Model identifier",
        default=config.model if config.provider == provider else model_default,
    )

    api_key_value = config.api_key
    base_url_value = config.base_url
    command_template = config.external_cli.command_template

    if provider in {
        AIProvider.OPENAI,
        AIProvider.ANTHROPIC,
        AIProvider.GEMINI,
        AIProvider.OPENAI_COMPATIBLE,
    }:
        api_key_value = Prompt.ask(
            "API key (leave blank to keep existing)",
            default=api_key_value,
            password=True,
        )

    if provider in {AIProvider.OLLAMA, AIProvider.OPENAI_COMPATIBLE}:
        default_url = (
            base_url_value
            if base_url_value
            else "http://localhost:11434/v1"
            if provider == AIProvider.OLLAMA
            else "http://localhost:4000/v1"
        )
        base_url_value = Prompt.ask("Base URL", default=default_url)

    if provider in {
        AIProvider.CODEX_CLI,
    }:
        codex_transport_options = [mode.value for mode in CodexTransport]
        try:
            default_transport_idx = codex_transport_options.index(
                config.codex_transport.value
            )
        except ValueError:
            default_transport_idx = 0
        codex_transport_choice = _select_option(
            shell=shell,
            title="Codex transport:",
            options=codex_transport_options,
            default_idx=default_transport_idx,
        )
        if codex_transport_choice is None:
            print_warning("Setup cancelled by user.")
            return
        config.codex_transport = CodexTransport(codex_transport_choice)

        profile = get_external_cli_profile(provider)
        profile_default_template = (
            profile.default_prompt_command_template
            if profile
            else _default_cli_template(provider)
        )
        profile_default_auth_check = (
            profile.default_auth_check_command if profile else ""
        )
        command_template = profile_default_template
        auth_check_command = profile_default_auth_check
        preflight_enabled = Confirm.ask(
            "Enable preflight checks before running prompts?",
            default=config.external_cli.preflight_enabled,
        )
        config.external_cli.auth_check_command = auth_check_command
        config.external_cli.preflight_enabled = preflight_enabled
        if profile:
            print_info(f"Selected profile: {profile.display_name}")
            print_info(f"Login hint: {profile.login_hint}")
            print_info(f"Docs: {profile.docs_url}")
        accepted = Confirm.ask(
            "Codex subscription mode sends prompts/context to OpenAI. Continue?",
            default=False,
        )
        if not accepted:
            print_warning("Setup cancelled by user.")
            return

    privacy_mode_options = [mode.value for mode in AIPrivacyMode]
    try:
        default_privacy_idx = privacy_mode_options.index(config.privacy_mode.value)
    except ValueError:
        default_privacy_idx = 0
    privacy_mode_choice = _select_option(
        shell=shell,
        title="Privacy mode:",
        options=privacy_mode_options,
        default_idx=default_privacy_idx,
    )
    if privacy_mode_choice is None:
        print_warning("Setup cancelled by user.")
        return
    privacy_mode = AIPrivacyMode(privacy_mode_choice)
    if privacy_mode != AIPrivacyMode.LOCAL_ONLY and provider in {
        AIProvider.OPENAI,
        AIProvider.ANTHROPIC,
        AIProvider.GEMINI,
        AIProvider.OPENAI_COMPATIBLE,
    }:
        accepted = Confirm.ask(
            "Cloud mode may send sensitive data to third-party providers. Continue?",
            default=False,
        )
        if not accepted:
            print_warning("Setup cancelled by user.")
            return

    _print_setup_summary(
        provider=provider,
        model=model_value,
        privacy_mode=privacy_mode,
        base_url=base_url_value,
        api_key=api_key_value,
        command_template=command_template,
        auth_check_command=config.external_cli.auth_check_command,
        preflight_enabled=config.external_cli.preflight_enabled,
        codex_transport=config.codex_transport,
    )
    if not Confirm.ask("Save this AI configuration?", default=True):
        print_warning("Setup cancelled by user.")
        return

    config.provider = provider
    config.model = model_value
    config.api_key = api_key_value
    config.base_url = base_url_value
    config.privacy_mode = privacy_mode
    config.external_cli.command_template = command_template
    path = save_ai_config(config)
    shell._ai_service = None
    marked_path = mark_sensitive(str(path), "path")
    print_success(f"AI configuration saved to {marked_path}.")
    _print_post_setup_next_steps(provider)
    run_ask_doctor(shell)


def run_ask_status(shell: Any) -> None:
    """Display safe AI backend configuration status."""
    config = load_ai_config()
    status = masked_status(config)
    lines = [
        f"enabled={status['enabled']}",
        f"provider={status['provider']}",
        f"backend_kind={status['backend_kind']}",
        f"model={status['model']}",
        f"model_ref={status['model_ref']}",
        f"privacy_mode={status['privacy_mode']}",
        f"streaming={status['streaming']}",
    ]
    if status["base_url"]:
        lines.append(f"base_url={status['base_url']}")
    if status["api_key_masked"]:
        lines.append(f"api_key={status['api_key_masked']}")
    lines.append(f"external_cli_configured={status['external_cli_configured']}")
    if status["provider"] == AIProvider.CODEX_CLI.value:
        lines.append(f"codex_transport={status['codex_transport']}")
    lines.append(
        f"external_cli_preflight_enabled={status['external_cli_preflight_enabled']}"
    )
    lines.append(
        "external_cli_auth_check_configured="
        f"{status['external_cli_auth_check_configured']}"
    )
    print_info("AI status:\n" + "\n".join(lines))


def run_ask_usage(shell: Any, argv: list[str]) -> None:
    """Show accumulated AI usage and provider limits."""
    if argv and argv[0].lower() == "budget":
        _run_ask_usage_budget(argv[1:])
        return

    window = "day"
    if argv:
        candidate = argv[0].lower()
        if candidate in {"day", "week", "all"}:
            window = candidate
        else:
            print_warning("Unknown usage window. Use: day | week | all.")
            return

    events = _load_ai_usage_events()
    summary = _summarize_usage_events(events=events, window=window)
    budget = _load_ai_usage_budget()
    budget_rows = _build_budget_rows(summary=summary, budget=budget)

    title = f"[bold]AI Usage ({window})[/bold]"
    body_lines = [
        f"events={summary['events']}",
        f"tokens={summary['tokens']}",
        f"cost_usd={summary['cost_usd']:.6f}",
    ]
    print_panel(
        "\n".join(body_lines),
        title=title,
        border_style="cyan",
        padding=(0, 1),
        spacing="after",
    )

    provider_rows = summary["providers"]
    if provider_rows:
        table = Table(
            title="[bold]Local Usage (ADscan Ledger)[/bold]",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Provider", style="cyan")
        table.add_column("Events", style="white")
        table.add_column("Tokens", style="white")
        table.add_column("Cost USD", style="green")
        for provider, data in sorted(provider_rows.items()):
            table.add_row(
                provider,
                str(data.get("events", 0)),
                str(data.get("tokens", 0)),
                f"{float(data.get('cost_usd', 0.0)):.6f}",
            )
        print_table(table, spacing="after")

    if budget_rows:
        budget_table = Table(
            title="[bold]Local Budget (ADscan Ledger)[/bold]",
            show_header=True,
            header_style="bold cyan",
        )
        budget_table.add_column("Budget", style="cyan")
        budget_table.add_column("Used", style="white")
        budget_table.add_column("Remaining", style="green")
        budget_table.add_column("Utilization", style="magenta")
        for row in budget_rows:
            budget_table.add_row(*row)
        print_table(budget_table, spacing="after")

    runtime_rows, runtime_fetched_at = _build_runtime_limit_rows(shell)
    if runtime_rows:
        _print_global_limits_notice(fetched_at=runtime_fetched_at)
        _print_metrics_table(
            title="[bold]Global Account Limits (Live Codex)[/bold]",
            rows=runtime_rows,
        )
    else:
        print_info("Global account limits (Live Codex): No disponible.")


def run_ask_doctor(shell: Any) -> None:
    """Validate AI backend readiness and print actionable hints."""
    service = shell._get_ai_service()
    if service is None:
        return

    ready, reason = service.validate_backend_ready()
    if ready:
        print_success("AI backend check passed.")
        return

    print_warning("AI backend check failed.")
    print_info(reason)


def run_ask_login(shell: Any, *, backend: str) -> None:
    """Run provider login flow for local subscription backend."""
    if backend != "codex":
        print_error("Only `codex` backend login is currently supported.")
        return
    profile = get_external_cli_profile(AIProvider.CODEX_CLI)
    if profile is None:
        print_error("Codex profile is unavailable.")
        return
    if not shutil.which(profile.binary_name):
        print_error("Codex CLI is not installed or not in PATH.")
        print_info("Install Codex in the runtime image and retry `ask login codex`.")
        return

    argv = shlex.split(profile.default_login_command)
    proc = _run_external_cli_command(
        shell=shell,
        argv=argv,
        capture_output=False,
        timeout=900,
    )
    if proc is None:
        print_error("Failed to start Codex login command.")
        return
    if proc.returncode != 0:
        print_error("Codex login failed.")
        return

    print_success("Codex login completed.")
    run_ask_auth_status(shell, backend="codex")


def run_ask_logout(shell: Any, *, backend: str) -> None:
    """Run provider logout flow for local subscription backend."""
    if backend != "codex":
        print_error("Only `codex` backend logout is currently supported.")
        return
    profile = get_external_cli_profile(AIProvider.CODEX_CLI)
    if profile is None:
        print_error("Codex profile is unavailable.")
        return
    if not shutil.which(profile.binary_name):
        print_error("Codex CLI is not installed or not in PATH.")
        return

    argv = shlex.split(profile.default_logout_command)
    proc = _run_external_cli_command(
        shell=shell,
        argv=argv,
        capture_output=True,
        timeout=120,
    )
    if proc is None:
        print_error("Failed to run Codex logout command.")
        return
    if proc.returncode != 0:
        details = (proc.stderr or proc.stdout or "").strip()
        print_error(f"Codex logout failed. {details}")
        return
    print_success("Codex logout completed.")


def run_ask_auth_status(shell: Any, *, backend: str) -> None:
    """Check provider authentication status for local subscription backend."""
    if backend != "codex":
        print_error("Only `codex` backend auth status is currently supported.")
        return
    profile = get_external_cli_profile(AIProvider.CODEX_CLI)
    if profile is None:
        print_error("Codex profile is unavailable.")
        return
    if not shutil.which(profile.binary_name):
        print_error("Codex CLI is not installed or not in PATH.")
        return

    config = load_ai_config()
    auth_cmd = config.external_cli.auth_check_command.strip()
    if not auth_cmd:
        auth_cmd = profile.default_auth_check_command
    auth_cmd = normalize_external_cli_auth_check_command(
        AIProvider.CODEX_CLI,
        auth_cmd,
    )
    argv = shlex.split(auth_cmd)
    proc = _run_external_cli_command(
        shell=shell,
        argv=argv,
        capture_output=True,
        timeout=30,
    )
    if proc is None:
        print_error("Failed to run Codex auth status command.")
        return

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        details = stderr or stdout
        if details:
            print_warning(f"Codex auth check failed: {details}")
        else:
            print_warning("Codex auth check failed with non-zero exit code.")
        print_info("If needed, run `ask login codex` and complete browser sign-in.")
        return

    print_success("Codex auth check passed.")
    if stdout:
        print_info(stdout)


def run_ask_codex_schema(shell: Any) -> None:
    """Export and validate Codex app-server JSON schema bundle."""
    profile = get_external_cli_profile(AIProvider.CODEX_CLI)
    if profile is None:
        print_error("Codex profile is unavailable.")
        return
    if not shutil.which(profile.binary_name):
        print_error("Codex CLI is not installed or not in PATH.")
        print_info("Install Codex in the runtime image and retry `ask codex-schema`.")
        return

    state_dir = get_state_dir() / "codex_schema"
    output_dir = state_dir / "json-schema"
    metadata_path = state_dir / "metadata.json"
    state_dir.mkdir(parents=True, exist_ok=True)
    output_dir_tmp = state_dir / "json-schema.tmp"
    if output_dir_tmp.exists():
        shutil.rmtree(output_dir_tmp, ignore_errors=True)

    with tempfile.TemporaryDirectory(prefix="adscan-codex-schema-") as tmp_raw:
        tmp_dir = Path(tmp_raw)
        argv = ["codex", "app-server", "generate-json-schema", "--out", str(tmp_dir)]
        print_info_debug(f"Exporting Codex app-server schema bundle: {argv}")
        proc = _run_external_cli_command(
            shell=shell,
            argv=argv,
            capture_output=True,
            timeout=180,
        )
        if proc is None:
            print_error("Failed to run codex schema generation command.")
            return
        if proc.returncode != 0:
            details = (proc.stderr or proc.stdout or "").strip()
            print_error(f"Codex schema generation failed. {details}")
            return

        protocol_path = tmp_dir / "codex_app_server_protocol.schemas.json"
        if not protocol_path.exists():
            print_error("Generated schema bundle is missing protocol root schema.")
            return
        valid, reason, payload = _validate_codex_protocol_schema_file(protocol_path)
        if not valid:
            print_error(f"Generated protocol schema is invalid: {reason}")
            return

        shutil.copytree(tmp_dir, output_dir_tmp, dirs_exist_ok=True)

    if output_dir.exists():
        shutil.rmtree(output_dir, ignore_errors=True)
    output_dir_tmp.replace(output_dir)

    codex_version = _resolve_codex_cli_version(shell=shell)
    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "codex_cli_version": codex_version,
        "protocol_title": str(payload.get("title", "")),
        "schema_file_count": _count_schema_files(output_dir),
        "protocol_schema_path": str(output_dir / "codex_app_server_protocol.schemas.json"),
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    marked_bundle = mark_sensitive(str(output_dir), "path")
    marked_meta = mark_sensitive(str(metadata_path), "path")
    print_success("Codex app-server schema bundle exported and validated.")
    print_info(f"Schema bundle: {marked_bundle}")
    print_info(f"Metadata: {marked_meta}")


def _run_single_prompt(shell: Any, prompt: str) -> None:
    """Execute one ask request and print result."""
    service = shell._get_ai_service()
    if service is None:
        return
    print_info_debug(f"AI prompt: {prompt}")
    if service.config.ask.streaming:
        chunks: list[str] = []
        for chunk in service.ask_stream(prompt):
            chunks.append(chunk)
        response = "".join(chunks).strip()
    else:
        response = service.ask_once(prompt)

    metadata = getattr(service, "last_response_metadata", {}) or {}
    _print_ai_prompt_usage_debug(metadata)
    _print_ai_response(response=response, metadata=metadata)
    _record_ai_usage_event(metadata)


def _run_ask_usage_budget(argv: list[str]) -> None:
    """Manage local AI usage budget configuration."""
    budget = _load_ai_usage_budget()
    if not argv or argv[0].lower() == "show":
        print_info(
            "AI usage budget:\n"
            f"daily_budget_usd={budget['daily_budget_usd']:.6f}\n"
            f"weekly_budget_usd={budget['weekly_budget_usd']:.6f}"
        )
        return

    scope = argv[0].lower()
    if scope == "clear":
        if len(argv) != 1:
            print_warning("Usage: ask usage budget clear")
            return
        budget["daily_budget_usd"] = 0.0
        budget["weekly_budget_usd"] = 0.0
        _save_ai_usage_budget(budget)
        print_success("AI usage budgets cleared.")
        return
    if len(argv) != 2:
        print_warning("Usage: ask usage budget <daily|weekly> <amount_usd>")
        return
    if scope not in {"daily", "weekly"}:
        print_warning("Budget scope must be `daily` or `weekly`.")
        return
    try:
        amount = float(argv[1])
    except ValueError:
        print_warning("Budget amount must be numeric.")
        return
    if amount < 0:
        print_warning("Budget amount must be >= 0.")
        return

    key = f"{scope}_budget_usd"
    budget[key] = amount
    _save_ai_usage_budget(budget)
    print_success(f"AI {scope} budget updated to {amount:.6f} USD.")


def _print_ai_response(*, response: str, metadata: dict[str, Any]) -> None:
    """Render AI response with premium panel UX and runtime metadata."""
    subtitle_parts: list[str] = []
    provider = str(metadata.get("provider", "")).strip()
    backend = str(metadata.get("backend", "")).strip()
    model = metadata.get("model")
    reasoning_effort = metadata.get("reasoning_effort")
    status = str(metadata.get("status", "")).strip()
    latency_ms = metadata.get("latency_ms")

    if provider:
        subtitle_parts.append(f"provider={provider}")
    if backend:
        subtitle_parts.append(f"backend={backend}")
    if isinstance(model, str) and model.strip():
        subtitle_parts.append(f"model={model.strip()}")
    if isinstance(reasoning_effort, str) and reasoning_effort.strip():
        subtitle_parts.append(f"effort={reasoning_effort.strip()}")
    if status:
        subtitle_parts.append(f"status={status}")
    if isinstance(latency_ms, int) and latency_ms > 0:
        subtitle_parts.append(f"latency={latency_ms / 1000:.2f}s")

    subtitle = " | ".join(subtitle_parts) if subtitle_parts else None
    subtitle_markup = f"[dim]{subtitle}[/dim]" if subtitle else None
    print_panel(
        response.strip() or "(empty response)",
        title="[bold]AI[/bold]",
        subtitle=subtitle_markup,
        border_style="cyan",
        padding=(0, 1),
        expand=True,
        spacing="after",
    )

    _print_ai_usage_and_limits(metadata)


def _print_ai_usage_and_limits(metadata: dict[str, Any]) -> None:
    """Render separated global (account) and local (ADscan) usage sections."""
    global_rows: list[tuple[str, str, str, str]] = []
    local_rows: list[tuple[str, str, str, str]] = []
    rate_limits = metadata.get("rate_limits")
    if isinstance(rate_limits, dict):
        global_rows.extend(_format_rate_limit_rows(rate_limits))
        account_plan = metadata.get("account_plan")
        if isinstance(account_plan, str) and account_plan.strip():
            global_rows.append(("plan", account_plan.strip(), "-", "-"))

    usage_input = metadata.get("usage_input_tokens")
    usage_output = metadata.get("usage_output_tokens")
    usage_total = metadata.get("usage_total_tokens")
    usage_cost = metadata.get("usage_cost_usd")
    if any(
        isinstance(value, int)
        for value in (usage_input, usage_output, usage_total)
    ):
        local_rows.append(
            (
                "tokens",
                str(usage_total if isinstance(usage_total, int) else "-"),
                (
                    f"in={usage_input if isinstance(usage_input, int) else '-'} "
                    f"out={usage_output if isinstance(usage_output, int) else '-'}"
                ),
                "-",
            )
        )
    if isinstance(usage_cost, float):
        local_rows.append(("cost_usd", f"{usage_cost:.6f}", "-", "provider"))

    if not global_rows and not local_rows:
        return

    if global_rows:
        _print_global_limits_notice(
            fetched_at=_coerce_timestamp(metadata.get("rate_limits_fetched_at_utc"))
        )
        _print_metrics_table(
            title="[bold]Global Account Limits (Codex)[/bold]",
            rows=global_rows,
        )

    if local_rows:
        _print_metrics_table(
            title="[bold]Local Usage (ADscan Only)[/bold]",
            rows=local_rows,
        )


def _print_ai_prompt_usage_debug(metadata: dict[str, Any]) -> None:
    """Print compact debug usage summary for the current AI prompt."""
    prompt_chars = metadata.get("request_prompt_chars")
    prompt_est_tokens = metadata.get("request_prompt_estimated_tokens")
    usage_input = metadata.get("usage_input_tokens")
    usage_output = metadata.get("usage_output_tokens")
    usage_total = metadata.get("usage_total_tokens")
    usage_cost = metadata.get("usage_cost_usd")

    parts: list[str] = []
    if isinstance(prompt_chars, int):
        parts.append(f"prompt_chars={prompt_chars}")
    if isinstance(prompt_est_tokens, int):
        parts.append(f"prompt_est_tokens={prompt_est_tokens}")
    if isinstance(usage_input, int):
        parts.append(f"input_tokens={usage_input}")
    if isinstance(usage_output, int):
        parts.append(f"output_tokens={usage_output}")
    if isinstance(usage_total, int):
        parts.append(f"total_tokens={usage_total}")
    if isinstance(usage_cost, float):
        parts.append(f"cost_usd={usage_cost:.6f}")

    if not parts:
        return
    print_info_debug("AI prompt usage summary: " + " | ".join(parts))


def _print_metrics_table(*, title: str, rows: list[tuple[str, str, str, str]]) -> None:
    """Render one generic metrics table for AI runtime stats."""
    if not rows:
        return
    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Used", style="white")
    table.add_column("Remaining", style="green")
    table.add_column("Reset", style="magenta")
    for metric, used, remaining, reset in rows:
        table.add_row(metric, used, remaining, reset)
    print_table(table, spacing="after")


def _print_global_limits_notice(*, fetched_at: str | None) -> None:
    """Explain that Codex limits are account-wide and show fetch timestamp."""
    note = (
        "Global account limits (Codex, all clients). "
        "These values include usage outside ADscan."
    )
    if fetched_at:
        note += f" fetched_at={fetched_at}"
    print_info(note)


def _format_rate_limit_rows(rate_limits: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """Convert codex rate limit payload into printable table rows."""
    rows: list[tuple[str, str, str, str]] = []
    primary = rate_limits.get("primary")
    secondary = rate_limits.get("secondary")
    if isinstance(primary, dict):
        rows.append(_format_rate_limit_row("primary", primary))
    if isinstance(secondary, dict):
        rows.append(_format_rate_limit_row("secondary", secondary))
    return rows


def _format_rate_limit_row(
    label: str,
    window: dict[str, Any],
) -> tuple[str, str, str, str]:
    """Format one codex rate-limit window row."""
    used = window.get("usedPercent")
    used_percent = int(used) if isinstance(used, int) else 0
    remaining_percent = max(0, 100 - used_percent)
    duration = window.get("windowDurationMins")
    duration_label = _format_window_duration(duration)
    resets_at = _format_reset_timestamp(window.get("resetsAt"))
    metric_label = f"{label} ({duration_label})" if duration_label else label
    return (metric_label, f"{used_percent}%", f"{remaining_percent}%", resets_at)


def _format_window_duration(duration_mins: Any) -> str:
    """Format rate-limit window duration."""
    if not isinstance(duration_mins, int) or duration_mins <= 0:
        return "-"
    if duration_mins % 10080 == 0:
        weeks = duration_mins // 10080
        return f"{weeks}w"
    if duration_mins % 1440 == 0:
        days = duration_mins // 1440
        return f"{days}d"
    if duration_mins % 60 == 0:
        hours = duration_mins // 60
        return f"{hours}h"
    return f"{duration_mins}m"


def _format_reset_timestamp(value: Any) -> str:
    """Format unix timestamp reset value to UTC readable string."""
    if not isinstance(value, int) or value <= 0:
        return "-"
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _usage_events_path() -> Path:
    """Return JSONL ledger path for AI usage events."""
    return get_state_dir() / "ai_usage_events.jsonl"


def _usage_budget_path() -> Path:
    """Return JSON budget configuration path for AI usage."""
    return get_state_dir() / "ai_usage_budget.json"


def _record_ai_usage_event(metadata: dict[str, Any]) -> None:
    """Append one usage event to local JSONL ledger."""
    status = str(metadata.get("status", "")).strip().lower()
    if not status:
        return
    event = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "provider": str(metadata.get("provider", "")),
        "backend": str(metadata.get("backend", "")),
        "model": metadata.get("model"),
        "status": status,
        "latency_ms": metadata.get("latency_ms"),
        "tokens": metadata.get("usage_total_tokens", 0),
        "cost_usd": metadata.get("usage_cost_usd", 0.0),
    }
    path = _usage_events_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def _load_ai_usage_events() -> list[dict[str, Any]]:
    """Load usage event ledger from JSONL file."""
    path = _usage_events_path()
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    events.append(payload)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
    return events


def _summarize_usage_events(*, events: list[dict[str, Any]], window: str) -> dict[str, Any]:
    """Summarize usage events for selected window: day/week/all."""
    now = datetime.now(timezone.utc)
    filtered: list[dict[str, Any]] = []
    for event in events:
        timestamp = _parse_event_timestamp(event.get("timestamp_utc"))
        if timestamp is None:
            continue
        if window == "day" and (now - timestamp).total_seconds() > 86400:
            continue
        if window == "week" and (now - timestamp).total_seconds() > 7 * 86400:
            continue
        filtered.append(event)

    tokens = 0
    cost_usd = 0.0
    providers: dict[str, dict[str, Any]] = {}
    for event in filtered:
        provider = str(event.get("provider", "")).strip() or "unknown"
        event_tokens = event.get("tokens", 0)
        event_cost = event.get("cost_usd", 0.0)
        if isinstance(event_tokens, int):
            tokens += event_tokens
        if isinstance(event_cost, (int, float)):
            cost_usd += float(event_cost)

        row = providers.setdefault(provider, {"events": 0, "tokens": 0, "cost_usd": 0.0})
        row["events"] += 1
        if isinstance(event_tokens, int):
            row["tokens"] += event_tokens
        if isinstance(event_cost, (int, float)):
            row["cost_usd"] += float(event_cost)

    return {
        "events": len(filtered),
        "tokens": tokens,
        "cost_usd": cost_usd,
        "providers": providers,
    }


def _parse_event_timestamp(value: Any) -> datetime | None:
    """Parse ISO timestamp from usage event."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_ai_usage_budget() -> dict[str, float]:
    """Load AI usage budget configuration."""
    path = _usage_budget_path()
    default_budget = {
        "daily_budget_usd": 0.0,
        "weekly_budget_usd": 0.0,
    }
    if not path.exists():
        return default_budget
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return default_budget
        daily = payload.get("daily_budget_usd", 0.0)
        weekly = payload.get("weekly_budget_usd", 0.0)
        return {
            "daily_budget_usd": float(daily) if isinstance(daily, (int, float)) else 0.0,
            "weekly_budget_usd": float(weekly) if isinstance(weekly, (int, float)) else 0.0,
        }
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return default_budget


def _save_ai_usage_budget(budget: dict[str, float]) -> None:
    """Persist AI usage budget configuration."""
    path = _usage_budget_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(budget, indent=2, sort_keys=True), encoding="utf-8")


def _build_budget_rows(
    *,
    summary: dict[str, Any],
    budget: dict[str, float],
) -> list[tuple[str, str, str, str]]:
    """Build budget utilization rows for usage summary table."""
    events = _load_ai_usage_events()
    day_summary = _summarize_usage_events(events=events, window="day")
    week_summary = _summarize_usage_events(events=events, window="week")

    rows: list[tuple[str, str, str, str]] = []
    daily_budget = float(budget.get("daily_budget_usd", 0.0))
    weekly_budget = float(budget.get("weekly_budget_usd", 0.0))

    if daily_budget > 0:
        used = float(day_summary.get("cost_usd", 0.0))
        rows.append(_budget_row(label="daily_usd", used=used, budget=daily_budget))
    if weekly_budget > 0:
        used = float(week_summary.get("cost_usd", 0.0))
        rows.append(_budget_row(label="weekly_usd", used=used, budget=weekly_budget))

    # When no explicit budget is configured, show current window totals as reference.
    if not rows:
        rows.append(
            (
                "window_cost_usd",
                f"{float(summary.get('cost_usd', 0.0)):.6f}",
                "-",
                "-",
            )
        )
    return rows


def _budget_row(*, label: str, used: float, budget: float) -> tuple[str, str, str, str]:
    """Build one budget row."""
    remaining = max(0.0, budget - used)
    utilization = (used / budget * 100.0) if budget > 0 else 0.0
    return (
        label,
        f"{used:.6f}",
        f"{remaining:.6f}",
        f"{utilization:.1f}%",
    )


def _build_runtime_limit_rows(shell: Any) -> tuple[list[tuple[str, str, str, str]], str | None]:
    """Build provider runtime limits rows and fetch timestamp when available."""
    service = shell._get_ai_service()
    if service is None:
        return [], None
    try:
        runtime = service.get_runtime_snapshot()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return [], None
    if not isinstance(runtime, dict):
        return [], None

    rows: list[tuple[str, str, str, str]] = []
    fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rate_limits = runtime.get("rate_limits")
    if isinstance(rate_limits, dict):
        rows.extend(_format_rate_limit_rows(rate_limits))
    account_plan = runtime.get("account_plan")
    if isinstance(account_plan, str) and account_plan.strip():
        rows.append(("plan", account_plan.strip(), "-", "-"))
    return rows, fetched_at if rows else None


def _coerce_timestamp(value: Any) -> str | None:
    """Normalize ISO timestamp to short UTC string for CLI notes."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _run_interactive_ask(shell: Any) -> None:
    """Run interactive `ask` session until user exits."""
    service = shell._get_ai_service()
    if service is None:
        return
    print_info("AI interactive mode. Type 'exit' to close.")
    while True:
        prompt = Prompt.ask("ask")
        if prompt.strip().lower() in {"exit", "quit", ":q"}:
            break
        if not prompt.strip():
            continue
        _run_single_prompt(shell, prompt)


def _default_model_for_provider(provider: AIProvider) -> str:
    """Return default model identifier for given provider."""
    if provider == AIProvider.OPENAI:
        return "gpt-4o-mini"
    if provider == AIProvider.ANTHROPIC:
        return "claude-3-5-sonnet-latest"
    if provider == AIProvider.GEMINI:
        return "gemini-2.0-flash"
    if provider == AIProvider.OLLAMA:
        return "llama3.2:latest"
    if provider == AIProvider.OPENAI_COMPATIBLE:
        return "gpt-4o-mini"
    if provider == AIProvider.CODEX_CLI:
        return "codex"
    return "default"


def _default_cli_template(provider: AIProvider) -> str:
    """Return conservative command template examples for CLI backends."""
    profile = get_external_cli_profile(provider)
    if profile:
        return profile.default_prompt_command_template
    return ""


def _print_provider_overview() -> None:
    """Print concise provider overview for setup wizard."""
    cloud_api = ", ".join(
        [
            AIProvider.OPENAI.value,
            AIProvider.ANTHROPIC.value,
            AIProvider.GEMINI.value,
            AIProvider.OLLAMA.value,
            AIProvider.OPENAI_COMPATIBLE.value,
        ]
    )
    print_info(f"API providers: {cloud_api}")
    for profile in list_external_cli_profiles():
        print_info(
            f"Subscription/local CLI: {profile.provider.value} -> {profile.display_name}"
        )


def run_ask_help() -> None:
    """Print quick usage reference for the ask command."""
    print_info(
        "ask command usage:\n"
        "  ask setup\n"
        "  ask status\n"
        "  ask usage\n"
        "  ask usage week\n"
        "  ask usage budget show\n"
        "  ask usage budget daily 10\n"
        "  ask usage budget weekly 50\n"
        "  ask usage budget clear\n"
        "  ask doctor\n"
        "  ask codex-schema\n"
        "  ask help\n"
        "  ask login codex\n"
        "  ask auth-status codex\n"
        "  ask logout codex\n"
        "  ask clear\n"
        '  ask "<prompt>"\n'
        "  ask\n\n"
        "SMB telemetry note (internal):\n"
        "  Event `smb_sensitive_data_analysis` outcomes are documented in:\n"
        "  docs/internal-telemetry-smb-sensitive-data.md"
    )


def _select_option(
    *,
    shell: Any,
    title: str,
    options: list[str],
    default_idx: int = 0,
) -> str | None:
    """Select one option using questionary UI with a safe fallback.

    Args:
        shell: Active shell instance.
        title: Prompt title shown to the operator.
        options: Selectable string options.
        default_idx: Default option index.

    Returns:
        Selected option value, or None when cancelled.
    """
    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        idx = selector(title, options, default_idx)
        if idx is None:
            return None
        if 0 <= int(idx) < len(options):
            return options[int(idx)]
        return None

    return Prompt.ask(
        title,
        choices=options,
        default=options[default_idx] if 0 <= default_idx < len(options) else options[0],
    )


def _print_setup_summary(
    *,
    provider: AIProvider,
    model: str,
    privacy_mode: AIPrivacyMode,
    base_url: str,
    api_key: str,
    command_template: str,
    auth_check_command: str,
    preflight_enabled: bool,
    codex_transport: CodexTransport,
) -> None:
    """Print a concise setup summary before persisting configuration."""
    api_key_state = "configured" if api_key.strip() else "not configured"
    lines = [
        "AI setup summary:",
        f"provider={provider.value}",
        f"model={model}",
        f"privacy_mode={privacy_mode.value}",
    ]
    if base_url.strip():
        lines.append(f"base_url={base_url.strip()}")
    if provider in {
        AIProvider.OPENAI,
        AIProvider.ANTHROPIC,
        AIProvider.GEMINI,
        AIProvider.OPENAI_COMPATIBLE,
    }:
        lines.append(f"api_key={api_key_state}")
    if provider == AIProvider.CODEX_CLI:
        lines.append(f"codex_transport={codex_transport.value}")
        lines.append(f"command_template={command_template}")
        lines.append(f"auth_check_command={auth_check_command}")
        lines.append(f"preflight_enabled={preflight_enabled}")
    print_info("\n".join(lines))


def _print_post_setup_next_steps(provider: AIProvider) -> None:
    """Print provider-specific next steps after setup."""
    if provider == AIProvider.CODEX_CLI:
        print_info(
            "Next steps for Codex subscription mode:\n"
            "  1) ask login codex\n"
            "  2) ask auth-status codex\n"
            "  3) ask doctor\n"
            '  4) ask "hello"'
        )
        return

    print_info('Next steps:\n  1) ask doctor\n  2) ask "hello"')


def _run_external_cli_command(
    *,
    shell: Any,
    argv: list[str],
    capture_output: bool,
    timeout: int,
) -> subprocess.CompletedProcess[str] | None:
    """Execute local external CLI command with safe argv invocation."""
    if not argv:
        return None

    runner = getattr(shell, "command_runner", None) or default_runner
    command_env = _build_external_cli_subprocess_env()
    try:
        return runner.run(
            CommandSpec(
                command=argv,
                timeout=timeout,
                shell=False,
                capture_output=capture_output,
                text=True,
                check=False,
                env=command_env,
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error_debug(f"External CLI command failed: {type(exc).__name__}: {exc}")
        return None


def _build_external_cli_subprocess_env() -> dict[str, str] | None:
    """Return clean env for external CLI commands in frozen runtime."""
    if not getattr(sys, "frozen", False):
        return None
    return get_clean_env_for_compilation()


def _resolve_codex_cli_version(*, shell: Any) -> str:
    """Resolve best-effort Codex CLI version string."""
    proc = _run_external_cli_command(
        shell=shell,
        argv=["codex", "--version"],
        capture_output=True,
        timeout=20,
    )
    if proc is None or proc.returncode != 0:
        return "unknown"
    value = (proc.stdout or "").strip()
    return value or "unknown"


def _validate_codex_protocol_schema_file(
    path: Path,
) -> tuple[bool, str, dict[str, Any]]:
    """Validate minimum protocol schema invariants expected by ADscan."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return False, f"JSON parse failed: {exc}", {}

    if not isinstance(payload, dict):
        return False, "Schema root must be a JSON object.", {}
    if str(payload.get("title", "")).strip() != "CodexAppServerProtocol":
        return False, "Unexpected schema title.", payload

    definitions = payload.get("definitions")
    if not isinstance(definitions, dict):
        return False, "Missing 'definitions' object.", payload
    required_defs = {
        "JSONRPCRequest",
        "JSONRPCResponse",
        "JSONRPCError",
        "JSONRPCNotification",
        "ServerNotification",
        "ServerRequest",
    }
    missing = sorted(def_name for def_name in required_defs if def_name not in definitions)
    if missing:
        return False, f"Missing protocol definitions: {', '.join(missing)}", payload
    return True, "ok", payload


def _count_schema_files(path: Path) -> int:
    """Return number of generated JSON schema files in bundle directory."""
    return sum(1 for file_path in path.rglob("*.json") if file_path.is_file())
