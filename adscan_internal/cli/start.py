"""Start command orchestration helpers.

This module contains small, dependency-light helpers used by `handle_start`
to keep `adscan.py` slimmer while preserving the exact runtime behaviour.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal
import ipaddress
import time
import os
import re
import sys

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_warning,
    print_instruction,
    telemetry,
    print_exception,
    print_panel,
    print_success,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.cli.ci_events import emit_phase
from adscan_internal.cli.session_preflight import (
    SessionPreflightConfig,
    SessionPreflightDeps,
    run_session_preflight,
)
from rich.prompt import Confirm, Prompt
from rich.text import Text
from adscan_internal.workspaces.subpaths import domain_relpath
from adscan_internal.cli.common import (
    build_lab_event_fields,
    mark_workspace_start_scan_completed,
    should_show_workspace_getting_started,
)
from adscan_internal.cli.dns import (
    confirm_domain_pdc_mapping,
    finalize_domain_context,
    infer_domain_from_candidate_ip,
    infer_domain_from_fqdn,
    offer_a_record_fallback,
    persist_pdc_preflight_result,
    preflight_domain_pdc,
    prompt_known_domain_and_pdc_interactive,
)
from adscan_internal.services.network_preflight_service import (
    assess_target_reachability,
    get_interface_ipv4_addresses,
)


@dataclass(frozen=True)
class _NetworkPreflightCheck:
    """One network preflight validation result row."""

    name: str
    status: Literal["ok", "warn", "fail"]
    detail: str
    suggestion: str | None = None


_LAB_STRONG_INFERENCE_THRESHOLD = 0.90
_USER_CONFIRMED_LAB_STATES = {"manual", "accepted_inference"}

_DOMAIN_INFERENCE_METHOD_COPY: dict[str, tuple[str, str, str]] = {
    "hosts": (
        "Domain inferred from /etc/hosts.",
        "Host",
        "[bold]🧩 Domain Inference[/bold]",
    ),
    "ldap": (
        "Domain inferred from LDAP fingerprinting.",
        "LDAP result",
        "[bold]🧩 Domain Inference (LDAP)[/bold]",
    ),
    "smb": (
        "Domain inferred from SMB fingerprinting.",
        "SMB result",
        "[bold]🧩 Domain Inference (SMB)[/bold]",
    ),
    "ptr": (
        "Domain inferred from reverse DNS (PTR).",
        "PTR hostname",
        "[bold]🧩 Domain Inference[/bold]",
    ),
}


def _has_explicit_lab_context(shell: Any) -> bool:
    """Return True when the current lab context came from explicit user input.

    Inferred contexts always populate ``lab_inference_source``. This lets us
    distinguish user-selected provider/lab values from tentative, replaceable
    inference results.
    """
    has_context = bool(
        getattr(shell, "lab_provider", None) or getattr(shell, "lab_name", None)
    )
    if getattr(shell, "lab_confirmation_state", None) in _USER_CONFIRMED_LAB_STATES:
        return has_context
    return has_context and not getattr(shell, "lab_inference_source", None)


def _infer_domain_from_candidate_ip_with_ux(
    shell: Any,
    *,
    candidate_ip: str,
    mode_label: str,
    timeout_seconds: int = 60,
    interactive: bool | None = None,
) -> str | None:
    """Infer a domain from a candidate DC/DNS IP and render consistent UX."""
    interactive_mode = bool(sys.stdin.isatty()) if interactive is None else interactive
    marked_ip = mark_sensitive(candidate_ip, "ip")
    print_info(
        "Trying automatic domain inference from the DC/DNS IP "
        "(/etc/hosts -> LDAP -> SMB -> PTR)..."
    )

    inferred_domain, method, hostname = infer_domain_from_candidate_ip(
        shell,
        candidate_ip=candidate_ip,
        timeout_seconds=timeout_seconds,
    )
    if not inferred_domain or not method:
        return None

    headline, value_label, title = _DOMAIN_INFERENCE_METHOD_COPY.get(
        method,
        (
            "Domain inferred automatically.",
            "Result",
            "[bold]🧩 Domain Inference[/bold]",
        ),
    )

    marked_domain = mark_sensitive(inferred_domain, "domain")
    marked_host = mark_sensitive(hostname, "host") if hostname else None
    value = (
        f"{marked_domain} (host: {marked_host})"
        if method in {"ldap", "smb"} and marked_host
        else marked_host or marked_domain
    )
    print_panel(
        f"[bold]{headline}[/bold]\n\n"
        f"IP: {marked_ip}\n"
        f"{value_label}: {value}\n"
        f"Domain: {marked_domain}\n\n"
        "[bold]Next:[/bold] Validate the domain/PDC via DNS SRV.",
        title=title,
        border_style="green",
        padding=(1, 2),
    )
    telemetry.capture(
        "domain_inference",
        properties={
            "mode": mode_label,
            "method": method,
            "result": "success",
            "interactive": interactive_mode,
        },
    )

    if not interactive_mode:
        return inferred_domain

    if Confirm.ask(
        Text(f"Use {marked_domain} and validate?", style="cyan"),
        default=True,
    ):
        return inferred_domain
    return None


def _reconcile_hostname_domain_with_ip_fingerprints(
    shell: Any,
    *,
    hostname: str,
    candidate_ip: str,
    hostname_domain: str,
    mode_label: str,
    timeout_seconds: int = 60,
    interactive: bool | None = None,
) -> tuple[str | None, str | None]:
    """Cross-check hostname-suffix inference against the resolved IP fingerprint."""
    interactive_mode = bool(sys.stdin.isatty()) if interactive is None else interactive
    ip_domain, method, discovered_host = infer_domain_from_candidate_ip(
        shell,
        candidate_ip=candidate_ip,
        timeout_seconds=timeout_seconds,
    )
    marked_hostname = mark_sensitive(hostname, "host")
    marked_ip = mark_sensitive(candidate_ip, "ip")
    marked_hostname_domain = mark_sensitive(hostname_domain, "domain")

    if not ip_domain or not method:
        print_info_debug(
            f"[domain_infer] Hostname-only cross-check could not infer a domain from "
            f"{marked_ip}; keeping hostname-derived domain {marked_hostname_domain} "
            f"for {marked_hostname}."
        )
        telemetry.capture(
            "hostname_domain_crosscheck",
            properties={
                "mode": mode_label,
                "result": "ip_inference_unavailable",
            },
        )
        return hostname_domain, None

    marked_ip_domain = mark_sensitive(ip_domain, "domain")
    if ip_domain == hostname_domain:
        print_info_debug(
            f"[domain_infer] Hostname-only cross-check matched via {method}: "
            f"{marked_hostname_domain} for {marked_hostname} -> {marked_ip}"
        )
        telemetry.capture(
            "hostname_domain_crosscheck",
            properties={
                "mode": mode_label,
                "result": "match",
                "method": method,
            },
        )
        method_label = {
            "hosts": "/etc/hosts",
            "ldap": "LDAP",
            "smb": "SMB",
            "ptr": "PTR",
        }.get(method, method.upper())
        confidence_line = (
            f"Cross-check: {method_label} confirmed {marked_hostname_domain}"
        )
        return hostname_domain, confidence_line

    detail_label = {
        "hosts": "Resolved host",
        "ldap": "LDAP fingerprint",
        "smb": "SMB fingerprint",
        "ptr": "PTR result",
    }.get(method, "IP inference")
    detail_value = (
        f"{marked_ip_domain} (host: {mark_sensitive(discovered_host, 'host')})"
        if discovered_host and method in {"ldap", "smb"}
        else marked_ip_domain
    )
    print_panel(
        "[bold yellow]The hostname suffix and the resolved IP do not point to the same domain.[/bold yellow]\n\n"
        f"Hostname: {marked_hostname}\n"
        f"Resolved IP: {marked_ip}\n"
        f"Hostname-derived domain: {marked_hostname_domain}\n"
        f"{detail_label}: {detail_value}\n\n"
        f"[bold]Recommended:[/bold] Use {marked_ip_domain} from the {detail_label.lower()}, "
        "then validate it via DNS SRV.",
        title="[bold]🧩 Hostname vs IP Domain Check[/bold]",
        border_style="yellow",
        padding=(1, 2),
    )
    print_info_debug(
        f"[domain_infer] Hostname-only cross-check mismatch: hostname_domain="
        f"{marked_hostname_domain} ip_domain={marked_ip_domain} method={method} "
        f"hostname={marked_hostname} ip={marked_ip}"
    )
    telemetry.capture(
        "hostname_domain_crosscheck",
        properties={
            "mode": mode_label,
            "result": "mismatch",
            "method": method,
        },
    )

    if not interactive_mode:
        print_warning(
            "Hostname-derived domain did not match the resolved IP fingerprint. "
            "Using the IP-derived domain for validation."
        )
        return ip_domain, None

    if Confirm.ask(
        Text(
            f"Use {marked_ip_domain} instead of {marked_hostname_domain}? (recommended)",
            style="cyan",
        ),
        default=True,
    ):
        return ip_domain, None

    if Confirm.ask(
        Text(
            f"Keep {marked_hostname_domain} from the hostname suffix and continue?",
            style="cyan",
        ),
        default=False,
    ):
        return hostname_domain, None
    return None, None


def _current_lab_inference_confidence(shell: Any) -> float | None:
    """Return the current inference confidence, normalized to float."""
    raw_value = getattr(shell, "lab_inference_confidence", None)
    if raw_value is None:
        return None
    try:
        return float(raw_value)
    except (TypeError, ValueError):
        return None


def _should_replace_existing_inference(shell: Any, new_confidence: float) -> bool:
    """Return True when a new inference should replace the current one."""
    if _has_explicit_lab_context(shell):
        return False
    current_confidence = _current_lab_inference_confidence(shell)
    if current_confidence is None:
        return True
    return float(new_confidence) >= current_confidence


def _apply_lab_inference_result_to_shell(shell: Any, result: Any) -> bool:
    """Apply an inferred lab result to the shell when policy allows it.

    Stronger or first-time inference results may replace older inferred values.
    Explicit user-selected context is preserved.
    """
    if not _should_replace_existing_inference(shell, float(result.confidence)):
        return False

    explicit_provider = bool(
        getattr(shell, "lab_provider", None)
        and not getattr(shell, "lab_inference_source", None)
    )
    explicit_lab = bool(
        getattr(shell, "lab_name", None)
        and not getattr(shell, "lab_inference_source", None)
    )

    if not getattr(shell, "type", None):
        shell.type = result.workspace_type

    if result.lab_provider and not explicit_provider:
        shell.lab_provider = result.lab_provider

    if result.lab_name and not explicit_lab:
        existing_provider = getattr(shell, "lab_provider", None)
        if not existing_provider or existing_provider == result.lab_provider:
            shell.lab_name = result.lab_name
            shell.lab_name_whitelisted = result.lab_name_whitelisted

    shell.lab_inference_source = result.source.value
    shell.lab_inference_confidence = float(result.confidence)
    shell.lab_confirmation_state = None
    return True


def _clear_inferred_lab_context(shell: Any) -> None:
    """Clear inferred lab metadata and inferred lab values from the shell."""
    if getattr(shell, "lab_inference_source", None):
        shell.lab_provider = None
        shell.lab_name = None
        shell.lab_name_whitelisted = None
    shell.lab_inference_source = None
    shell.lab_inference_confidence = None
    if getattr(shell, "lab_confirmation_state", None) == "accepted_inference":
        shell.lab_confirmation_state = None


def _set_user_selected_lab_context(
    shell: Any,
    *,
    provider: str,
    lab_name: str,
    whitelisted: bool,
) -> None:
    """Persist a manual operator choice as explicit lab context."""
    shell.lab_provider = provider
    shell.lab_name = lab_name
    shell.lab_name_whitelisted = whitelisted
    shell.lab_inference_source = None
    shell.lab_inference_confidence = None
    shell.lab_confirmation_state = "manual"


def _accept_inferred_lab_context(shell: Any) -> None:
    """Mark the current inferred lab context as confirmed by the operator."""
    if getattr(shell, "lab_provider", None) or getattr(shell, "lab_name", None):
        shell.lab_confirmation_state = "accepted_inference"


def maybe_offer_post_scan_lab_confirmation(shell: Any) -> None:
    """Prompt once at scan end when lab context is weak or still unknown.

    Policy:
    - Strong inference (>= 0.90): accepted silently.
    - Weak inference (< 0.90): prompt once to accept or skip.
    - Unknown lab/provider: no free-text prompt; keep provider context and use
      `provider/unknown` downstream when applicable.
    """
    if getattr(shell, "type", None) != "ctf":
        return
    if getattr(shell, "_lab_prompt_shown", False):
        return

    provider = getattr(shell, "lab_provider", None)
    lab_name = getattr(shell, "lab_name", None)
    inference_source = getattr(shell, "lab_inference_source", None)
    confidence = _current_lab_inference_confidence(shell)
    confirmation_state = getattr(shell, "lab_confirmation_state", None)

    if confirmation_state == "accepted_inference":
        return

    should_prompt = not provider or (
        inference_source
        and (confidence is None or confidence < _LAB_STRONG_INFERENCE_THRESHOLD)
    )
    if not should_prompt:
        return

    shell._lab_prompt_shown = True
    shell.console.print()

    if inference_source and provider and lab_name:
        marked_provider = mark_sensitive(provider, "provider")
        marked_lab = mark_sensitive(lab_name, "lab")
        percent = int(round((confidence or 0.0) * 100))
        print_panel(
            "[bold]ADscan inferred the target lab from scan/workspace context.[/bold]\n\n"
            f"Provider: {marked_provider}\n"
            f"Lab: {marked_lab}\n"
            f"Source: {inference_source}\n"
            f"Confidence: {percent}%\n\n"
            "[dim]Accept to keep it, or reject to leave the machine as unknown.[/dim]",
            title="[bold]Lab Confirmation[/bold]",
            border_style="cyan",
            padding=(1, 2),
        )
        try:
            if Confirm.ask("Use this inferred lab context?", default=True):
                _accept_inferred_lab_context(shell)
                if hasattr(shell, "save_workspace_data"):
                    try:
                        shell.save_workspace_data()
                    except Exception:  # noqa: BLE001
                        pass
                return
        except (EOFError, KeyboardInterrupt):
            return

        # Explicit rejection means we should not keep the weak inferred value.
        _clear_inferred_lab_context(shell)
        print_info_debug(
            "[domain_inference] post-scan confirmation: free-text lab entry disabled; "
            "falling back to provider/unknown when provider context exists"
        )
        if hasattr(shell, "save_workspace_data"):
            try:
                shell.save_workspace_data()
            except Exception:  # noqa: BLE001
                pass
    return


def _workspace_has_domain_data(shell: Any) -> bool:
    """Return True when the workspace has domain data worth cleaning.

    We only prompt the user to clean the workspace when there is existing domain
    state (e.g. previous scans) to avoid a noisy prompt on first run.
    """

    try:
        domains_data = getattr(shell, "domains_data", None)
    except Exception:
        return False
    return bool(domains_data)


_WORKSPACE_CLEAN_CONFIRMATION = "I want to clean the workspace"


def _prompt_workspace_cleanup(shell: Any) -> None:
    """Prompt to clean the workspace with a strong confirmation."""
    if not _workspace_has_domain_data(shell):
        return

    print_panel(
        "[bold]Workspace Cleanup[/bold]\n\n"
        "Before starting a new scan, you can clean the workspace to ensure a fresh start.\n\n"
        "[bold yellow]⚠️  When to clean:[/bold yellow]\n"
        "• If you're experiencing scan issues or errors\n"
        "• If previous scan data might be causing conflicts\n"
        "• If domain information seems corrupted or outdated\n"
        "• If you want to start completely fresh\n\n"
        "[bold green]✓ Safe to skip:[/bold green]\n"
        "• If your previous scans completed successfully\n"
        "• If you want to continue building on existing data\n"
        "• If you're resuming a scan or adding new domains\n\n"
        "[bold cyan]💡 Alternative options:[/bold cyan]\n"
        "• You can clean manually later with: [yellow]clear_all[/yellow]\n"
        "• Or create a new workspace with: [yellow]workspace create[/yellow]\n\n"
        "[dim]Note: Cleaning preserves variables.json, technical_report.json, and command history[/dim]",
        title="[bold]🧹 Workspace Preparation[/bold]",
        border_style="yellow",
        padding=(1, 2),
    )

    prompt_text = Text(
        "Do you want to clean the workspace before starting the scan?", style="cyan"
    )
    if not Confirm.ask(
        prompt_text,
        default=False,
    ):
        return

    print_panel(
        "[bold yellow]Type this phrase exactly to confirm cleanup:[/bold yellow]\n\n"
        f"[bold]{_WORKSPACE_CLEAN_CONFIRMATION}[/bold]\n\n"
        "[dim]Tip: this is case-sensitive. Type `exit` to cancel.[/dim]",
        title="[bold]⚠️ Confirmation Required[/bold]",
        border_style="yellow",
        padding=(1, 2),
    )

    for _ in range(5):
        confirmation_prompt = Text("Type exactly: ", style="cyan")
        confirmation_prompt.append(_WORKSPACE_CLEAN_CONFIRMATION, style="bold yellow")
        confirmation_prompt.append(" (or 'exit' to cancel)")
        confirmation = Prompt.ask(
            confirmation_prompt,
            default="",
            show_default=False,
        )
        confirmation_clean = confirmation.strip()
        if confirmation_clean == "exit":
            print_warning("Workspace cleanup cancelled by operator.")
            return
        if confirmation_clean == _WORKSPACE_CLEAN_CONFIRMATION:
            break
        print_warning("Confirmation phrase did not match.")
    else:
        print_warning("Workspace cleanup cancelled; confirmation failed.")
        return

    print_info("[dim]Cleaning workspace...[/dim]")
    shell.do_clear_all("")
    print_success("[bold]✓[/bold] Workspace cleaned successfully!")
    time.sleep(0.5)  # Small delay for better UX


def _select_option_interactive(
    shell: Any,
    *,
    message: str,
    options: list[str],
    default_index: int = 0,
) -> int | None:
    """Select an option interactively with a best-effort UX.

    Prefers the shell's `*_questionary_select` UI when available, otherwise falls
    back to a numbered Prompt.
    """
    try:
        selector = getattr(shell, "_questionary_select", None)
        if callable(selector):
            try:
                idx = selector(message, options, default_index)
            except TypeError:
                idx = selector(message, options)
            if idx is None:
                return None
            if isinstance(idx, int) and 0 <= idx < len(options):
                return idx
    except Exception:
        pass

    from rich.prompt import Prompt
    from rich.text import Text

    numbered = [f"{i + 1}. {opt}" for i, opt in enumerate(options)]
    print_panel(
        "[bold]Choose one option:[/bold]\n\n" + "\n".join(numbered),
        title="[bold]🧭 Selection[/bold]",
        border_style="yellow",
        padding=(1, 2),
    )
    choices = [str(i + 1) for i in range(len(options))]
    selected = Prompt.ask(
        Text(message, style="cyan"),
        choices=choices,
        default=str(default_index + 1),
    )
    try:
        idx = int(selected) - 1
    except ValueError:
        return None
    if 0 <= idx < len(options):
        return idx
    return None


def _handle_start_wizard_interrupt(
    shell: Any,
    *,
    command_name: str,
    switch_command: str | None = None,
) -> str:
    """Guide recovery when a start wizard prompt is cancelled.

    Returns one of ``retry``, ``switch``, or ``return``. Non-interactive
    sessions always return ``return`` because there is no safe recovery path.
    """
    telemetry.capture(
        "start_wizard_interrupted",
        properties={
            "command": command_name,
            "interactive": bool(sys.stdin.isatty()),
            "switch_command": switch_command,
        },
    )
    print_info_debug(
        f"[start] interactive setup interrupted for {command_name}; "
        f"switch_target={switch_command or 'none'}"
    )

    if not sys.stdin.isatty():
        print_warning(
            f"{command_name} setup was cancelled. Returning without starting the scan."
        )
        return "return"

    bullet_lines = [
        "• no scan has started yet",
        "• your current workspace remains unchanged",
        "• you can retry the wizard or return to the CLI safely",
    ]
    if switch_command:
        bullet_lines.append(
            f"• if you opened the wrong wizard, switch to [bold]{switch_command}[/bold]"
        )

    print_panel(
        f"[bold]{command_name} setup was cancelled.[/bold]\n\n"
        "ADscan stopped the wizard before any scan execution started.\n\n"
        + "\n".join(bullet_lines),
        title="[bold]🧭 Start Setup Cancelled[/bold]",
        border_style="yellow",
        padding=(1, 2),
    )

    options = ["Retry this setup"]
    if switch_command:
        options.append(f"Switch to {switch_command}")
    options.append("Return to the CLI")
    action_idx = _select_option_interactive(
        shell,
        message="How do you want to continue?",
        options=options,
        default_index=0,
    )
    if action_idx == 0:
        return "retry"
    if switch_command and action_idx == 1:
        return "switch"
    return "return"


def _run_start_unauth_impl(shell, args: str | None) -> None:
    """Start unauthenticated scan using the legacy PentestShell implementation.

    This helper mirrors :meth:`PentestShell.do_start_unauth` while keeping the
    orchestration logic in this module so that `adscan.py` can be slimmer.
    """
    # Interactive configuration prompts
    if not shell._prompt_type_if_missing():
        return

    if not shell._prompt_interface_if_missing():
        return

    if not shell._prompt_auto_if_missing():
        return

    # Ask if user wants to clean workspace before starting scan (only if needed)
    _prompt_workspace_cleanup(shell)

    # Always show scan-type guidance (even in args mode) to steer credentialed users
    # towards start_auth. Only prompt when interactive so automation doesn't block.
    print_panel(
        "[bold]Scan Type Selection[/bold]\n\n"
        "• [bold cyan]Authenticated Scan[/bold cyan]: Recommended if you already have domain credentials\n"
        "  - Covers all unauthenticated checks plus authenticated enumeration\n"
        "  - More comprehensive results with better coverage\n"
        "  - Requires: domain name, PDC IP, username, and password/hash\n\n"
        "• [bold yellow]Unauthenticated Scan[/bold yellow]: For black-box scenarios without credentials\n"
        "  - Useful for discovering domains and obtaining initial access\n"
        "  - Limited to anonymous/guest access enumeration\n"
        "  - May require domain discovery if not known",
        title="[bold]🔐 Choose Scan Type[/bold]",
        border_style="cyan",
        padding=(1, 2),
    )

    if sys.stdin.isatty():
        cred_prompt = Text.assemble(
            ("Do you have domain credentials? ", "cyan"),
            ("(If yes, we recommend using ", ""),
            ("start_auth", "bold"),
            (" instead)", ""),
        )
        if Confirm.ask(cred_prompt, default=False):
            print_panel(
                "[bold]Switching to authenticated scan...[/bold]\n\n"
                "We'll guide you through:\n"
                "• Credentials (username + password/hash)\n"
                "• Target context (domain/DC) with validation\n\n"
                "[dim]Tip: If you don't have credentials after all, you can come back to start_unauth.[/dim]",
                title="[bold]🔐 Start Authenticated Scan[/bold]",
                border_style="green",
                padding=(1, 2),
            )
            run_start_auth(shell, None)
            return

        print_info("Continuing with unauthenticated scan")
    else:
        print_info(
            "[dim]Tip: If you have credentials, use `start_auth` for full coverage.[/dim]"
        )

    # Collect domain context: allow partial inputs (domain only, IP only, hostname only).
    known_domain: str | None = None
    known_pdc_ip: str | None = None
    skip_domain_discovery = False

    if not args:  # Only ask if domain not provided as argument
        print_panel(
            "Provide what you know to skip discovery:\n\n"
            "• Domain FQDN (e.g., contoso.local)\n"
            "• DC/DNS IP\n"
            "• DC hostname (FQDN)\n\n"
            "No info? Choose discovery and enter a host range.",
            title="[bold]🎯 Domain Context[/bold]",
            border_style="blue",
            padding=(1, 2),
        )

        if Confirm.ask(
            Text(
                "Do you know any domain information (domain/IP/hostname)?", style="cyan"
            ),
            default=True,
        ):
            context = _domain_context_wizard_for_unauth(shell)
            if context is not None:
                known_domain, known_pdc_ip = context
                skip_domain_discovery = True
                shell.hosts = known_pdc_ip
                shell.domains_data.setdefault(known_domain, {})["pdc"] = known_pdc_ip
                finalize_domain_context(
                    shell,
                    domain=known_domain,
                    pdc_ip=known_pdc_ip,
                    interactive=bool(sys.stdin.isatty()),
                )
                print_info(
                    f"Domain set to: {mark_sensitive(known_domain, 'domain')}\n"
                    f"DC/PDC set to: {mark_sensitive(known_pdc_ip, 'ip')}\n"
                    "[dim]Skipping host-range discovery, proceeding with direct enumeration...[/dim]"
                )

        if not skip_domain_discovery:
            from adscan_internal import print_warning

            print_info(
                "Host-range discovery mode enabled\n"
                "[dim]We'll scan the specified host range to discover domains first[/dim]"
            )
            print_warning(
                "[bold]Important:[/bold] Provide a range that actually contains DCs",
                panel=True,
                items=[
                    "Include AD members (workstations/servers)",
                    "LDAP (389) is preferred; SMB (445) is only a fallback",
                    "Single IP or CIDR (e.g., 10.10.10.100 or 10.10.10.0/24)",
                ],
            )

    # Args mode supports a few "shortcuts" for power users:
    # - `start_unauth <domain>` (attempt DNS-based PDC discovery)
    # - `start_unauth <domain> <dc_ip>` (validate and optionally correct to PDC)
    # - `start_unauth <dc_ip>` (attempt PTR-based domain inference, then validate)
    if args:
        import ipaddress

        parts = args.strip().split()
        if len(parts) not in {1, 2}:
            print_error("Usage: start_unauth <domain|dc_ip> [dc_ip]")
            return

        service = shell._get_dns_discovery_service()

        first = parts[0].strip()
        domain: str | None = None
        candidate_ip: str | None = None

        # Case: `start_unauth <dc_ip>`
        is_first_ip = False
        try:
            ipaddress.ip_address(first)
            is_first_ip = True
        except ValueError:
            is_first_ip = False

        if is_first_ip and len(parts) == 1:
            candidate_ip = first
            domain = _infer_domain_from_candidate_ip_with_ux(
                shell,
                candidate_ip=candidate_ip,
                mode_label="unauth",
                timeout_seconds=60,
                interactive=bool(sys.stdin.isatty()),
            )

            if not domain:
                if not sys.stdin.isatty():
                    print_error(
                        "Domain inference failed and interactive input is not available. "
                        "Provide the domain explicitly: `start_unauth <domain> <dc_ip>`."
                    )
                    return
                print_info(
                    "Could not infer the domain automatically; requesting input."
                )
                domain = (
                    Prompt.ask(
                        Text(
                            "Enter the domain name (e.g., contoso.local)", style="cyan"
                        )
                    )
                    .strip()
                    .lower()
                )
            if not domain or "." not in domain:
                print_error(
                    "Domain must be a FQDN (e.g., contoso.local), not a NetBIOS name."
                )
                return

        # Case: `start_unauth <domain> [dc_ip]`
        if not is_first_ip:
            domain = first.strip().lower()
            if "." not in domain:
                print_error(
                    "Domain must be a FQDN (e.g., contoso.local), not a NetBIOS name."
                )
                return

            candidate_ip = parts[1].strip() if len(parts) == 2 else None
            if candidate_ip:
                try:
                    ipaddress.ip_address(candidate_ip)
                except ValueError:
                    print_error(
                        f"Invalid DC/PDC IP address: {mark_sensitive(candidate_ip, 'ip')}"
                    )
                    return
            else:
                # Domain-only args: attempt to discover PDC via system DNS first.
                pdc_ip, pdc_hostname = service.discover_pdc(domain=domain)
                if pdc_ip:
                    marked_pdc = mark_sensitive(pdc_ip, "ip")
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_hostname = (
                        mark_sensitive(pdc_hostname, "hostname")
                        if pdc_hostname
                        else None
                    )
                    discovered_line = (
                        f"{marked_pdc} ({marked_hostname})"
                        if marked_hostname
                        else marked_pdc
                    )
                    print_panel(
                        "[bold]PDC discovered via DNS SRV.[/bold]\n\n"
                        f"Domain: {marked_domain}\n"
                        f"PDC (DNS SRV): {discovered_line}\n",
                        title="[bold]🧭 PDC Discovery[/bold]",
                        border_style="green",
                        padding=(1, 2),
                    )
                    if sys.stdin.isatty():
                        if Confirm.ask(
                            Text(
                                f"Validate and use {marked_pdc} for this scan?",
                                style="cyan",
                            ),
                            default=True,
                        ):
                            candidate_ip = pdc_ip
                    else:
                        candidate_ip = pdc_ip
                if not candidate_ip:
                    fallback_ip = offer_a_record_fallback(
                        shell=shell,
                        service=service,
                        domain=domain,
                        fallback_hint="use host-range discovery",
                        confirm=False,
                    )
                    if fallback_ip:
                        candidate_ip = fallback_ip

            if not candidate_ip:
                if not sys.stdin.isatty():
                    print_error(
                        "No DC/DNS IP provided and PDC discovery failed. Provide a DC IP: "
                        "`start_unauth <domain> <dc_ip>`."
                    )
                    return
                print_info("PDC discovery failed; please provide a DC/DNS IP.")
                candidate_ip = Prompt.ask(
                    Text(
                        "Enter a DC/DNS IP address for this domain (e.g., 10.10.10.100)",
                        style="cyan",
                    )
                ).strip()
                try:
                    ipaddress.ip_address(candidate_ip)
                except ValueError:
                    print_error(
                        f"Invalid DC/DNS IP address: {mark_sensitive(candidate_ip, 'ip')}"
                    )
                    return

        decision = preflight_domain_pdc(
            shell,
            domain=domain,
            candidate_ip=candidate_ip,
            interactive=bool(sys.stdin.isatty()),
            mode_label="unauth",
        )
        if decision.action == "reenter":
            validated = prompt_known_domain_and_pdc_interactive(
                shell, mode_label="unauth"
            )
            if validated is None:
                # Fall back to discovery flow.
                args = None
                known_domain = None
                known_pdc_ip = None
                skip_domain_discovery = False
            else:
                known_domain, known_pdc_ip = validated
                skip_domain_discovery = True
                shell.hosts = known_pdc_ip
                shell.domains_data.setdefault(known_domain, {})["pdc"] = known_pdc_ip
                if known_domain and known_pdc_ip:
                    finalize_domain_context(
                        shell,
                        domain=known_domain,
                        pdc_ip=known_pdc_ip,
                        interactive=bool(sys.stdin.isatty()),
                    )
        elif decision.action == "fallback":
            args = None
            known_domain = None
            known_pdc_ip = None
            skip_domain_discovery = False
        else:
            known_domain, known_pdc_ip = decision.domain, decision.pdc_ip
            skip_domain_discovery = True
            if known_pdc_ip:
                persist_pdc_preflight_result(shell, decision)
                shell.hosts = known_pdc_ip
                shell.domains_data.setdefault(known_domain, {})["pdc"] = known_pdc_ip
                finalize_domain_context(
                    shell,
                    domain=known_domain,
                    pdc_ip=known_pdc_ip,
                    interactive=bool(sys.stdin.isatty()),
                )

        if not skip_domain_discovery:
            # User opted to fall back to discovery mode, ignore the domain arg.
            if not shell._prompt_hosts_if_missing():
                return
            _warn_if_single_discovery_target(shell.hosts)
            target = shell.hosts
            domain = None
            known_domain = None
            known_pdc_ip = None
        else:
            computers_file = os.path.join(
                "domains",
                known_domain or domain,
                "enabled_computers_ips.txt",
            )
            if os.path.exists(computers_file) and os.path.getsize(computers_file) > 0:
                target = computers_file
            elif known_pdc_ip:
                target = known_pdc_ip
            else:
                print_error(
                    "Domain provided but no DC target is available. Provide a DC IP: "
                    "`start_unauth <domain> <pdc_ip>` or use domain discovery mode."
                )
                return

    else:
        # Original behavior using shell.hosts
        if skip_domain_discovery and known_domain:
            if not known_pdc_ip:
                print_error(
                    "Direct domain enumeration requires a DC IP. Choose domain discovery "
                    "or provide the PDC/DC IP when prompted."
                )
                return
            target = known_pdc_ip
            domain = known_domain
        else:
            if not shell._prompt_hosts_if_missing():
                return
            _warn_if_single_discovery_target(shell.hosts)

            target = shell.hosts
            domain = known_domain

    interactive_mode = bool(sys.stdin.isatty())
    if skip_domain_discovery and known_domain and known_pdc_ip:
        if not _run_start_network_preflight(
            shell,
            mode_label="start_unauth (known domain)",
            interface=getattr(shell, "interface", None),
            interactive=interactive_mode,
            target_ip=known_pdc_ip,
            require_dc_ports=True,
        ):
            return
    else:
        if not _run_start_network_preflight(
            shell,
            mode_label="start_unauth (discovery)",
            interface=getattr(shell, "interface", None),
            interactive=interactive_mode,
            hosts_expression=str(target),
        ):
            return

    # Professional scan initialization header
    from adscan_internal import print_operation_header

    scan_details = {
        "Scan Type": "Unauthenticated",
        "Workspace Type": shell.type.upper() if shell.type else "N/A",
        "Target": domain if domain else target,
        "Auto Mode": "Enabled" if shell.auto else "Disabled",
        "Interface": shell.interface,
    }

    if skip_domain_discovery and known_domain:
        scan_details["Mode"] = "Direct Enumeration (Domain Known)"
        if known_pdc_ip:
            scan_details["PDC/DC"] = known_pdc_ip

    print_operation_header(
        "Starting Unauthenticated Scan", details=scan_details, icon="🚀"
    )

    # Mark scan mode for telemetry
    shell.scan_mode = "unauth"
    shell.domain_validated_cred_counts = {}
    # Use a monotonic clock for scan timing so duration metrics are not
    # affected if the system clock is adjusted during the scan.
    shell.scan_start_time = time.monotonic()

    # Reset scan-level metrics for case studies
    # Note: Attack path metrics are computed from attack_graph.json at scan completion
    shell._scan_first_credential_time = None
    shell._scan_compromise_time = None

    # If domain is known, skip service discovery and proceed directly
    if skip_domain_discovery and known_domain:
        # Add domain to shell.domains if not already there
        if not hasattr(shell, "domains"):
            shell.domains = []
        if known_domain not in shell.domains:
            shell.domains.append(known_domain)
            shell.create_sub_workspace_for_domain(known_domain, known_pdc_ip)

        # Check DNS for the known domain
        if known_pdc_ip:
            dns_ok = shell.do_check_dns(known_domain, known_pdc_ip)
        else:
            dns_ok = shell.do_check_dns(known_domain)
        if not dns_ok:
            from adscan_internal import print_warning

            print_warning(
                f"[bold]⚠️  DNS resolution issue for domain[/bold] {mark_sensitive(known_domain, 'domain')}\n"
                "The scan will continue, but some enumeration may fail without proper DNS resolution."
            )

        if not _ensure_unauth_target_list(
            shell,
            domain=known_domain,
            pdc_ip=known_pdc_ip,
        ):
            return

        # Skip to enumeration for this domain
        _maybe_apply_domain_inference(shell, known_domain)
        mark_workspace_start_scan_completed(shell, "start_unauth")
        shell.workspace_save()
        if not shell._is_ctf_domain_pwned(known_domain):
            shell.ask_for_unauth_scan(known_domain)
    else:
        # Original flow: scan services to discover domains
        # List of services to scan
        # services = ['smb', 'rdp', 'winrm', 'mssql']
        services = ["smb"]
        # Telemetry: track unauthenticated scan start
        properties = {
            "type": shell.type,
            "interface": shell.interface,
            "auto": shell.auto,
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        properties["preflight_check_passed"] = bool(shell.preflight_check_passed)
        properties["preflight_check_fix_attempted"] = bool(
            shell.preflight_check_fix_attempted
        )
        properties["preflight_check_overridden"] = bool(
            shell.preflight_check_overridden
        )
        # Add workspace_id_hash to count unique workspaces per user
        # Hash combines TELEMETRY_ID + workspace_name for uniqueness across users
        if shell.current_workspace:
            import hashlib
            from adscan_internal.telemetry import TELEMETRY_ID

            workspace_unique_id = f"{TELEMETRY_ID}:{shell.current_workspace}"
            properties["workspace_id_hash"] = hashlib.sha256(
                workspace_unique_id.encode()
            ).hexdigest()[:12]
        telemetry.capture("start_unauth", properties)

        # Scan each service sequentially
        for service in services:
            if service == "smb" and not domain:
                from adscan_internal.cli.dns import (
                    select_domain_from_rows,
                    discover_domains_from_candidate_ips,
                    preflight_domain_pdc_from_candidates,
                )
                from adscan_internal.cli.nmap import (
                    discover_dc_candidates_with_nmap_details,
                )

                candidate_port_map = discover_dc_candidates_with_nmap_details(
                    shell, hosts=target, ports=[88, 389, 53]
                )
                candidates = sorted(candidate_port_map.keys())
                if not candidates:
                    marked_target = mark_sensitive(str(target), "host")
                    print_panel(
                        "[bold]No Domain Controllers Found[/bold]\n\n"
                        f"Scanned {marked_target} for AD core ports "
                        "(Kerberos 88, LDAP 389, DNS 53) and found no likely DCs.\n\n"
                        "[bold]Recommended next step:[/bold]\n"
                        "• Try a broader or different range that includes DCs\n\n"
                        "[bold]If you already know the domain + DC IP:[/bold]\n"
                        "• Run [bold]start_unauth <domain> <dc_ip>[/bold]\n",
                        title="[bold]⚠️  Domain Discovery[/bold]",
                        border_style="yellow",
                        padding=(1, 2),
                    )
                    continue

                summaries = discover_domains_from_candidate_ips(
                    shell,
                    candidate_ips=candidates,
                    candidate_open_ports=candidate_port_map,
                )
                if not summaries:
                    print_warning(
                        "No domains inferred from candidate DC/DNS IPs. "
                        "Try a broader range or provide domain + DC IP."
                    )
                    continue

                rows = [
                    (summary.domain, len(summary.candidate_ips), summary.methods)
                    for summary in summaries
                ]
                selected_domain = select_domain_from_rows(
                    shell,
                    rows=rows,
                    prompt="Multiple domains discovered. Select one to proceed:",
                    title="[bold]🧩 Domains Inferred[/bold]",
                )
                if not selected_domain:
                    return
                selected_summary = next(
                    summary
                    for summary in summaries
                    if summary.domain == selected_domain
                )

                decision = preflight_domain_pdc_from_candidates(
                    shell,
                    domain=selected_summary.domain,
                    candidate_ips=selected_summary.candidate_ips,
                    interactive=bool(sys.stdin.isatty()),
                    mode_label="unauth",
                    candidate_open_ports=candidate_port_map,
                )
                if decision.action != "use" or not decision.pdc_ip:
                    if decision.action == "reenter":
                        context = prompt_known_domain_and_pdc_interactive(
                            shell, mode_label="unauth"
                        )
                        if context is None:
                            return
                        known_domain, known_pdc_ip = context
                    else:
                        return
                else:
                    known_domain, known_pdc_ip = decision.domain, decision.pdc_ip

                if not hasattr(shell, "domains"):
                    shell.domains = []
                if known_domain not in shell.domains:
                    shell.domains.append(known_domain)
                    shell.create_sub_workspace_for_domain(known_domain, known_pdc_ip)

                persist_pdc_preflight_result(shell, decision)
                finalize_domain_context(
                    shell,
                    domain=known_domain,
                    pdc_ip=known_pdc_ip,
                    interactive=bool(sys.stdin.isatty()),
                )
                print_panel(
                    "[bold]Discovery Summary[/bold]\n\n"
                    f"Domain: {mark_sensitive(known_domain, 'domain')}\n"
                    f"PDC/DC: {mark_sensitive(known_pdc_ip, 'ip')}\n"
                    f"Candidates scanned: {len(selected_summary.candidate_ips)}\n\n"
                    "[dim]Proceeding with unauthenticated enumeration.[/dim]",
                    title="[bold]✅ Ready to Enumerate[/bold]",
                    border_style="green",
                    padding=(1, 2),
                )

                if not _ensure_unauth_target_list(
                    shell,
                    domain=known_domain,
                    pdc_ip=known_pdc_ip,
                ):
                    return

                _maybe_apply_domain_inference(shell, known_domain)
                shell.workspace_save()
                if not shell._is_ctf_domain_pwned(known_domain):
                    shell.ask_for_unauth_scan(known_domain)
                continue

            shell.scan_service(service, target, domain)


def _warn_if_single_discovery_target(hosts_expression: str | None) -> None:
    """Warn when discovery scope is a single host and may miss domain context."""
    target = str(hosts_expression or "").strip()
    if not target:
        return
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return

    print_warning(
        "[bold]Very narrow discovery scope detected:[/bold] single target host.",
        panel=True,
        items=[
            "Domain discovery may fail if this host is not AD-connected.",
            "Prefer a CIDR that includes likely DCs and AD members (e.g., /24).",
            "If possible, use a known DC/DNS IP via the domain context wizard.",
        ],
    )


def _extract_probe_ip_from_hosts_expression(hosts_expression: str | None) -> str | None:
    """Return a representative IPv4 from a hosts expression for route checks."""
    target = str(hosts_expression or "").strip()
    if not target:
        return None

    first_token = next((part.strip() for part in target.split(",") if part.strip()), "")
    if not first_token:
        return None

    try:
        return str(ipaddress.ip_address(first_token))
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(first_token, strict=False)
    except ValueError:
        network = None
    if network is not None:
        host_iter = network.hosts()
        first_host = next(host_iter, None)
        return str(first_host) if first_host else str(network.network_address)

    range_match = re.match(
        r"^(?P<prefix>\d{1,3}(?:\.\d{1,3}){2}\.)(?P<start>\d{1,3})-(?P<end>\d{1,3})$",
        first_token,
    )
    if range_match:
        candidate = f"{range_match.group('prefix')}{range_match.group('start')}"
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return None

    if "-" in first_token:
        left, _sep, _right = first_token.partition("-")
        left = left.strip()
        try:
            return str(ipaddress.ip_address(left))
        except ValueError:
            return None

    return None


def _build_network_preflight_panel_body(
    *,
    mode_label: str,
    interface: str,
    checks: list[_NetworkPreflightCheck],
    target_ip: str | None = None,
    hosts_expression: str | None = None,
) -> str:
    """Build a consistent, professional panel body for network preflight results."""
    lines = [
        "[bold]Pre-scan network validation detected issues.[/bold]",
        "",
        f"Mode: {mode_label}",
        f"Interface: {interface}",
    ]
    if target_ip:
        lines.append(f"Target: {mark_sensitive(target_ip, 'ip')}")
    elif hosts_expression:
        lines.append(f"Scope: {mark_sensitive(hosts_expression, 'host')}")
    lines.append("")

    status_icon = {"ok": "[green]✓[/green]", "warn": "[yellow]⚠[/yellow]", "fail": "[red]✗[/red]"}
    for check in checks:
        lines.append(f"{status_icon[check.status]} {check.name}: {check.detail}")

    suggestions = [check.suggestion for check in checks if check.suggestion]
    if suggestions:
        lines.append("")
        lines.append("[bold]Recommended actions:[/bold]")
        for suggestion in suggestions:
            lines.append(f"• {suggestion}")

    return "\n".join(lines)


def _run_start_network_preflight(
    shell: Any,
    *,
    mode_label: str,
    interface: str | None,
    interactive: bool,
    target_ip: str | None = None,
    hosts_expression: str | None = None,
    require_dc_ports: bool = False,
) -> bool:
    """Validate local interface/routing reachability before starting scans."""
    checks: list[_NetworkPreflightCheck] = []
    iface = (interface or "").strip()
    if not iface:
        checks.append(
            _NetworkPreflightCheck(
                name="Interface",
                status="fail",
                detail="No network interface configured.",
                suggestion="Set an interface before scanning (e.g., `set interface tun0`).",
            )
        )
    else:
        ipv4_addrs = get_interface_ipv4_addresses(iface)
        if not ipv4_addrs:
            checks.append(
                _NetworkPreflightCheck(
                    name="Interface",
                    status="fail",
                    detail=f"Interface '{iface}' has no IPv4 address assigned.",
                    suggestion="Reconnect VPN/tunnel and confirm interface has an IPv4 address.",
                )
            )
        else:
            marked_ip = mark_sensitive(ipv4_addrs[0], "ip")
            checks.append(
                _NetworkPreflightCheck(
                    name="Interface",
                    status="ok",
                    detail=f"Interface '{iface}' is up with IPv4 {marked_ip}.",
                )
            )

    probe_target = target_ip or _extract_probe_ip_from_hosts_expression(hosts_expression)
    if probe_target:
        route_assessment = assess_target_reachability(
            shell,
            target_ip=probe_target,
            expected_interface=iface or None,
            tcp_ports=(),
        ).route
        marked_probe = mark_sensitive(probe_target, "ip")
        if not route_assessment.ok:
            checks.append(
                _NetworkPreflightCheck(
                    name="Route check",
                    status="fail",
                    detail=f"No usable route to {marked_probe}.",
                    suggestion="Confirm VPN routing to the target subnet before scanning.",
                )
            )
        elif route_assessment.reason == "route_interface_mismatch":
            marked_src = (
                mark_sensitive(route_assessment.source_ip, "ip")
                if route_assessment.source_ip
                else "[unknown]"
            )
            checks.append(
                _NetworkPreflightCheck(
                    name="Route check",
                    status="warn",
                    detail=(
                        f"Route to {marked_probe} uses interface '{route_assessment.route_interface}' "
                        f"(source {marked_src}), not '{iface}'."
                    ),
                    suggestion="If this is unexpected, verify active VPN interface and policy routing.",
                )
            )
        else:
            marked_src = (
                mark_sensitive(route_assessment.source_ip, "ip")
                if route_assessment.source_ip
                else "[unknown]"
            )
            route_summary = (
                f"Route to {marked_probe} via interface '{route_assessment.route_interface}' (source {marked_src})."
                if route_assessment.route_interface
                else f"Route to {marked_probe} is present."
            )
            checks.append(
                _NetworkPreflightCheck(
                    name="Route check",
                    status="ok",
                    detail=route_summary,
                )
            )

    if require_dc_ports and target_ip:
        reachability = assess_target_reachability(
            shell,
            target_ip=target_ip,
            expected_interface=iface or None,
            tcp_ports=(53, 389, 445),
        )
        open_ports = list(reachability.open_ports)
        marked_target = mark_sensitive(target_ip, "ip")
        if not open_ports:
            checks.append(
                _NetworkPreflightCheck(
                    name="DC service reachability",
                    status="fail",
                    detail=f"Could not connect to TCP 53/389/445 on {marked_target}.",
                    suggestion="Verify routing/firewall rules and confirm the target is a DC/PDC.",
                )
            )
        else:
            checks.append(
                _NetworkPreflightCheck(
                    name="DC service reachability",
                    status="ok",
                    detail=f"Reachable ports on {marked_target}: {', '.join(str(p) for p in open_ports)}.",
                )
            )
            if 53 not in open_ports:
                checks.append(
                    _NetworkPreflightCheck(
                        name="DNS reachability",
                        status="warn",
                        detail=f"TCP 53 is not reachable on {marked_target}. DNS validation may fail.",
                        suggestion="Ensure DNS service on the selected DC/PDC is reachable from this host.",
                    )
                )

    failures = [check for check in checks if check.status == "fail"]
    warnings = [check for check in checks if check.status == "warn"]

    if not failures and not warnings:
        print_info_verbose(
            f"Network preflight passed for {mode_label} using interface '{iface}'."
        )
        return True

    panel_body = _build_network_preflight_panel_body(
        mode_label=mode_label,
        interface=iface or "[unset]",
        checks=checks,
        target_ip=target_ip,
        hosts_expression=hosts_expression,
    )
    panel_style = "red" if failures else "yellow"
    panel_title = "[bold]🛡️ Network Preflight[/bold]"
    print_panel(
        panel_body,
        title=panel_title,
        border_style=panel_style,
        padding=(1, 2),
    )

    telemetry.capture(
        "start_network_preflight_result",
        properties={
            "mode": mode_label,
            "has_failures": bool(failures),
            "warning_count": len(warnings),
            "target_provided": bool(target_ip),
            "hosts_expression_provided": bool(hosts_expression),
        },
    )

    if not failures:
        emit_phase("network_preflight")
        return True

    if interactive:
        continue_anyway = Confirm.ask(
            Text(
                "Continue scan anyway despite failed network preflight checks?",
                style="cyan",
            ),
            default=False,
        )
        if continue_anyway:
            print_warning("Continuing scan despite failed network preflight checks.")
            return True
        print_error("Scan aborted due to network preflight failures.")
        return False

    print_error(
        "Aborting scan due to network preflight failures "
        "(non-interactive mode)."
    )
    return False


def _ensure_unauth_target_list(
    shell: Any,
    *,
    domain: str,
    pdc_ip: str | None,
) -> bool:
    """Ensure we have a target list for unauthenticated SMB guest enumeration."""

    def _normalize_guest_target_tokens(raw_value: Any) -> list[str]:
        """Normalize guest SMB targets from comma/space-separated user input."""
        if isinstance(raw_value, (list, tuple, set)):
            tokens = [str(item).strip() for item in raw_value if str(item).strip()]
        else:
            raw = str(raw_value or "").strip()
            if not raw:
                return []
            tokens = re.split(r"[,\s]+", raw)
        normalized: list[str] = []
        seen: set[str] = set()
        for token in tokens:
            value = str(token).strip()
            if not value:
                continue
            key = value.casefold()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(value)
        return normalized

    def _set_guest_targets(tokens: list[str]) -> None:
        """Persist selected guest SMB targets in the domain runtime context."""
        domain_data = shell.domains_data.setdefault(domain, {})
        domain_data["guest_smb_targets"] = list(tokens)

    existing_targets = _normalize_guest_target_tokens(
        shell.domains_data.get(domain, {}).get("guest_smb_targets")
    )
    if existing_targets:
        _set_guest_targets(existing_targets)
        return True

    enabled_computers = domain_relpath(
        shell.domains_dir, domain, "enabled_computers_ips.txt"
    )
    smb_ips = domain_relpath(shell.domains_dir, domain, "smb", "ips.txt")

    for candidate in (enabled_computers, smb_ips):
        if os.path.exists(candidate) and os.path.getsize(candidate) > 0:
            return True

    if not sys.stdin.isatty():
        non_interactive_targets = _normalize_guest_target_tokens(
            getattr(shell, "hosts", None)
        )
        if not non_interactive_targets and pdc_ip:
            non_interactive_targets = [pdc_ip]
        if non_interactive_targets:
            _set_guest_targets(non_interactive_targets)
            marked_targets = mark_sensitive(" ".join(non_interactive_targets), "host")
            print_info(
                "No host list detected; defaulting guest SMB enumeration to "
                f"{marked_targets}."
            )
            return True
        return False

    marked_domain = mark_sensitive(domain, "domain")
    marked_pdc = mark_sensitive(pdc_ip, "ip") if pdc_ip else "[unknown]"
    print_panel(
        "[bold]We need a target list for guest SMB enumeration.[/bold]\n\n"
        f"Domain: {marked_domain}\n"
        f"PDC/DC: {marked_pdc}\n\n"
        "Guest share enumeration expects a list of target hosts. "
        "You can provide one or multiple ranges/IPs directly, supply your own file, "
        "or use only the validated PDC for a quick check.\n",
        title="[bold]🧭 SMB Targets Required[/bold]",
        border_style="yellow",
        padding=(1, 2),
    )

    options: list[str] = []
    if pdc_ip:
        options.append("Use only the validated PDC/DC (fast)")
    options.extend(
        [
            "Provide host ranges/IPs directly",
            "Provide a file with target IPs",
            "Cancel and return",
        ]
    )
    choice = _select_option_interactive(
        shell,
        message="Select how you want to provide SMB targets:",
        options=options,
        default_index=0,
    )
    if choice is None:
        return False

    selected = options[choice]
    if selected.startswith("Use only") and pdc_ip:
        _set_guest_targets([pdc_ip])
        print_info(
            "Target list created with the validated PDC/DC only "
            f"({mark_sensitive(pdc_ip, 'ip')})."
        )
        return True

    if selected.startswith("Provide host ranges"):
        from adscan_internal.cli.smb import confirm_large_smb_target_scope

        default_hosts = str(getattr(shell, "hosts", "") or pdc_ip or "").strip()
        while True:
            ranges_input = Prompt.ask(
                Text(
                    "Enter SMB target ranges/IPs "
                    "(comma/space-separated, e.g., 192.168.10.0/24, 192.168.11.0/24)",
                    style="cyan",
                ),
                default=default_hosts,
            ).strip()
            if not ranges_input:
                return False
            target_tokens = _normalize_guest_target_tokens(ranges_input)
            if not target_tokens:
                print_warning("No valid SMB targets were provided. Please try again.")
                continue
            if not confirm_large_smb_target_scope(
                shell,
                targets=target_tokens,
                prompt_context="Provide SMB targets",
            ):
                print_info(
                    "Large SMB target scope rejected. Enter a narrower scope."
                )
                default_hosts = ranges_input
                continue
            _set_guest_targets(target_tokens)
            shell.hosts = ", ".join(target_tokens)
            marked_targets = mark_sensitive(" ".join(target_tokens), "host")
            print_instruction(
                f"Guest SMB targets configured: {marked_targets}. "
                "Enumeration will run directly against these targets."
            )
            return True

    if selected.startswith("Provide a file"):
        while True:
            file_path = Prompt.ask(
                Text("Enter path to file with IPs/targets", style="cyan")
            ).strip()
            if not file_path:
                return False
            if not os.path.exists(file_path):
                print_warning("File not found. Please enter a valid path.")
                continue
            with open(file_path, encoding="utf-8") as handle:
                lines = [line.strip() for line in handle if line.strip()]
            if not lines:
                print_warning("The file is empty. Provide a file with targets.")
                continue
            target_tokens = _normalize_guest_target_tokens(" ".join(lines))
            if not target_tokens:
                print_warning("No valid targets were found in the file.")
                continue
            os.makedirs(os.path.dirname(smb_ips), exist_ok=True)
            with open(smb_ips, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
            _set_guest_targets([smb_ips])
            print_info(f"Loaded {len(lines)} target(s) into {smb_ips}.")
            return True

    return False


def _domain_context_wizard_for_unauth(shell: Any) -> tuple[str, str] | None:
    """Collect domain context for unauthenticated scans (includes blind discovery option)."""
    return _domain_context_wizard(shell, allow_blind=True, mode_label="unauth")


def _domain_context_wizard_for_auth(shell: Any) -> tuple[str, str] | None:
    """Collect domain context for authenticated scans (no blind discovery option)."""
    return _domain_context_wizard(shell, allow_blind=False, mode_label="auth")


def _domain_context_wizard(
    shell: Any,
    *,
    allow_blind: bool,
    mode_label: Literal["unauth", "auth"],
) -> tuple[str, str] | None:
    """Collect the best available (domain, dc_ip) context from partial user inputs.

    Args:
        shell: Interactive shell.
        allow_blind: When True, include a "I know nothing" option and return None.
        mode_label: Telemetry label describing which start flow is using the wizard.

    Returns:
        (domain, dc_ip) if enough information is confirmed to run direct enumeration,
        or None when the user opts out (or selects blind discovery).
    """
    import ipaddress

    from rich.prompt import Confirm, Prompt
    from rich.text import Text

    options = [
        "🌐 I know the domain (FQDN) and a DC/DNS IP (recommended)",
        "🌐 I know only the domain (FQDN)",
        "🧭 I know only a DC/DNS IP",
        "🧭 I know only a DC hostname (FQDN)",
    ]
    if allow_blind:
        options.append("🕳️ I know nothing (use host-range discovery)")

    selection = _select_option_interactive(
        shell,
        message="What do you know about the target?",
        options=options,
        default_index=2 if (os.getenv("CI") or not sys.stdin.isatty()) else 0,
    )
    if selection is None:
        return None
    if allow_blind and selection == 4:
        return None

    service = shell._get_dns_discovery_service()

    fallback_hint = (
        "use host-range discovery"
        if allow_blind
        else "re-enter values (or use start_unauth)"
    )

    def _prompt_domain() -> str | None:
        while True:
            domain_input = (
                Prompt.ask(
                    Text("Enter the domain name (e.g., contoso.local)", style="cyan")
                )
                .strip()
                .lower()
            )
            if not domain_input:
                return None
            if "." not in domain_input:
                print_warning(
                    f"[bold]⚠️  Invalid domain format:[/bold] {mark_sensitive(domain_input, 'domain')}\n"
                    "Domain must be a FQDN (e.g., [yellow]contoso.local[/yellow])"
                )
                continue
            return domain_input

    def _prompt_ip() -> str | None:
        while True:
            ip_input = Prompt.ask(
                Text("Enter a DC/DNS IP address (e.g., 10.10.10.100)", style="cyan"),
                default="",
            ).strip()
            if not ip_input:
                return None
            try:
                ipaddress.ip_address(ip_input)
            except ValueError:
                print_warning(
                    f"[bold]⚠️  Invalid IP address format:[/bold] {mark_sensitive(ip_input, 'ip')}\n"
                    "Please enter a valid IPv4 address (e.g., [yellow]10.10.10.100[/yellow])"
                )
                continue
            return ip_input

    def _confirm_and_preflight(domain: str, ip: str) -> tuple[str, str] | None:
        return confirm_domain_pdc_mapping(
            shell,
            domain=domain,
            candidate_ip=ip,
            interactive=True,
            mode_label=mode_label,
            on_reenter=lambda: prompt_known_domain_and_pdc_interactive(
                shell, mode_label=mode_label
            ),
        )

    # 0) domain + IP
    if selection == 0:
        return prompt_known_domain_and_pdc_interactive(shell, mode_label=mode_label)

    # 1) domain only
    if selection == 1:
        domain = _prompt_domain()
        if not domain:
            return None
        pdc_ip, pdc_hostname = service.discover_pdc(domain=domain)
        if pdc_ip:
            marked_domain = mark_sensitive(domain, "domain")
            marked_pdc = mark_sensitive(pdc_ip, "ip")
            marked_hostname = (
                mark_sensitive(pdc_hostname, "hostname") if pdc_hostname else None
            )
            discovered_line = (
                f"{marked_pdc} ({marked_hostname})" if marked_hostname else marked_pdc
            )
            print_panel(
                "[bold]PDC discovered via DNS SRV.[/bold]\n\n"
                f"Domain: {marked_domain}\n"
                f"PDC (DNS SRV): {discovered_line}\n\n"
                "[bold]Next:[/bold] Validate and use this DC/PDC.",
                title="[bold]🧭 PDC Discovery[/bold]",
                border_style="green",
                padding=(1, 2),
            )
            if Confirm.ask(
                Text(f"Validate and use {marked_pdc} for this scan?", style="cyan"),
                default=True,
            ):
                return _confirm_and_preflight(domain, pdc_ip)

        print_info(
            "No PDC found via SRV; trying A/hosts lookup for a DC/DNS candidate..."
        )
        fallback_ip = offer_a_record_fallback(
            shell=shell,
            service=service,
            domain=domain,
            fallback_hint=fallback_hint,
            confirm=False,
        )
        if fallback_ip:
            return _confirm_and_preflight(domain, fallback_ip)

        print_panel(
            "[bold]We couldn't discover the PDC from the domain name.[/bold]\n\n"
            f"Domain: {mark_sensitive(domain, 'domain')}\n\n"
            f"Provide a DC/DNS IP to continue, or {fallback_hint}.",
            title="[bold]🧭 Need More Information[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
        if Confirm.ask(
            Text("Do you know a DC/DNS IP for this domain?", style="cyan"),
            default=True,
        ):
            ip = _prompt_ip()
            if not ip:
                return None
            return _confirm_and_preflight(domain, ip)
        return None

    # 2) IP only
    if selection == 2:
        ip = _prompt_ip()
        if not ip:
            return None
        inferred_domain = _infer_domain_from_candidate_ip_with_ux(
            shell,
            candidate_ip=ip,
            mode_label=mode_label,
            timeout_seconds=60,
        )
        if inferred_domain:
            return _confirm_and_preflight(inferred_domain, ip)

        print_info("Could not infer the domain automatically; requesting input.")
        print_panel(
            "[bold]We couldn't infer the domain from this IP.[/bold]\n\n"
            f"IP: {mark_sensitive(ip, 'ip')}\n\n"
            f"Enter the domain name now, or {fallback_hint}.",
            title="[bold]🧩 Domain Inference Failed[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
        domain = _prompt_domain()
        if not domain:
            return None
        return _confirm_and_preflight(domain, ip)

    # 3) hostname only
    hostname = (
        Prompt.ask(
            Text(
                "Enter the DC hostname (FQDN) (e.g., dc01.contoso.local)", style="cyan"
            )
        )
        .strip()
        .lower()
    )
    if not hostname or "." not in hostname:
        print_warning("A DC hostname must be a FQDN (e.g., dc01.contoso.local).")
        return None
    inferred_domain = infer_domain_from_fqdn(hostname)
    if not inferred_domain:
        print_warning("Could not infer a domain from the provided hostname.")
        return None

    ip_candidates = service.resolve_ipv4_addresses_robust(hostname)
    if not ip_candidates:
        print_panel(
            "[bold]We couldn't resolve the DC hostname to an IP.[/bold]\n\n"
            f"Hostname: {mark_sensitive(hostname, 'host')}\n\n"
            f"If you know a DC/DNS IP, provide it to use as a resolver; otherwise {fallback_hint}.",
            title="[bold]🧭 Hostname Resolution Failed[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
        resolver_ip = _prompt_ip()
        if not resolver_ip:
            return None
        ip_candidates = service.resolve_ipv4_addresses_robust(
            hostname, resolver=resolver_ip
        )
        if not ip_candidates:
            return None

    chosen_ip = ip_candidates[0]
    if len(ip_candidates) > 1:
        opt = [f"{ip}" for ip in ip_candidates]
        idx = _select_option_interactive(
            shell,
            message="Multiple IPs found for that hostname. Choose one:",
            options=opt,
            default_index=0,
        )
        if idx is None:
            return None
        chosen_ip = ip_candidates[idx]

    reconciled_domain, crosscheck_line = _reconcile_hostname_domain_with_ip_fingerprints(
        shell,
        hostname=hostname,
        candidate_ip=chosen_ip,
        hostname_domain=inferred_domain,
        mode_label=mode_label,
        timeout_seconds=60,
        interactive=True,
    )
    if not reconciled_domain:
        return None
    inferred_domain = reconciled_domain

    marked_domain = mark_sensitive(inferred_domain, "domain")
    marked_ip = mark_sensitive(chosen_ip, "ip")
    marked_host = mark_sensitive(hostname, "host")
    context_lines = [
        "[bold]We derived domain and IP from the DC hostname.[/bold]",
        "",
        f"Hostname: {marked_host}",
        f"Resolved IP: {marked_ip}",
        f"Inferred domain: {marked_domain}",
    ]
    if crosscheck_line:
        context_lines.append(crosscheck_line)
    print_panel(
        "\n".join(context_lines),
        title="[bold]🧩 Hostname Context[/bold]",
        border_style="green",
        padding=(1, 2),
    )
    if not Confirm.ask(
        Text("Validate and proceed with these values?", style="cyan"),
        default=True,
    ):
        return None
    return _confirm_and_preflight(inferred_domain, chosen_ip)


def maybe_relaunch_into_venv(
    *,
    is_frozen: bool,
    is_venv: Callable[[], bool],
    venv_path: str,
    tools_install_dir: str,
    argv: list[str],
    script_path: str,
    track_docs_link_shown: Callable[[str, str], None],
) -> None:
    """Relaunch `adscan start` inside the venv when running as a script.

    Behaviour matches the original `handle_start` logic:
    - If not in venv and not frozen, execve into `<VENV_PATH>/bin/python`.
    - If venv python missing, print guidance and exit(1).
    - If execve fails, capture telemetry and exit(1).
    """
    if is_venv() or is_frozen:
        return

    print_info_verbose("Not in venv and running as script. Relaunching...")
    venv_python = os.path.join(venv_path, "bin", "python")
    if not os.path.exists(venv_python):
        print_error(f"Virtual environment Python not found at {venv_python}.")
        print_instruction("Please run: adscan install")
        docs_url = (
            "https://www.adscanpro.com/docs/guides/troubleshooting"
            "?utm_source=cli&utm_medium=install_error#virtualenv-setup"
        )
        print_info(f"💡 [link={docs_url}]Troubleshooting installation errors[/link]")
        track_docs_link_shown("install_error", docs_url)
        sys.exit(1)

    try:
        current_env = os.environ.copy()
        tool_paths = [os.path.join(venv_path, "bin")]
        if os.path.isdir(tools_install_dir):
            tool_paths.append(tools_install_dir)
            for item in os.listdir(tools_install_dir):
                item_path = os.path.join(tools_install_dir, item)
                if os.path.isdir(item_path):
                    tool_paths.append(item_path)
        current_env["PATH"] = (
            os.pathsep.join(tool_paths) + os.pathsep + current_env.get("PATH", "")
        )

        original_args = argv[1:]
        if original_args and original_args[0] == "start":
            exec_args = [venv_python, script_path] + original_args
        else:
            exec_args = [venv_python, script_path, "start"] + original_args

        print_info_verbose(f"Relaunching with: {' '.join(exec_args)}")
        os.execve(venv_python, exec_args, current_env)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to relaunch in virtual environment.")
        print_exception(show_locals=False, exception=exc)
        sys.exit(1)


def prepend_tools_to_path(*, tools_install_dir: str) -> None:
    """Prepend tool directories under `tools_install_dir` to PATH.

    This mirrors the original `handle_start` behaviour and is intentionally
    conservative (only adds tool subdirectories, not venv/bin).
    """
    current_env_path = os.environ.get("PATH", "")
    tool_bin_paths_to_add: list[str] = []
    if os.path.isdir(tools_install_dir):
        for tool_name_dir_item in os.listdir(tools_install_dir):
            tool_dir_path_item = os.path.join(tools_install_dir, tool_name_dir_item)
            if os.path.isdir(tool_dir_path_item):
                tool_bin_paths_to_add.append(tool_dir_path_item)
    if tool_bin_paths_to_add:
        os.environ["PATH"] = (
            os.pathsep.join(tool_bin_paths_to_add) + os.pathsep + current_env_path
        )


@dataclass(frozen=True)
class StartSessionConfig:
    """Configuration for the legacy `adscan start` flow."""

    venv_path: str
    tools_install_dir: str
    requested_pro: bool
    verbose_mode: bool
    debug_mode: bool


@dataclass(frozen=True)
class StartSessionDeps:
    """Dependency bundle for starting an interactive session."""

    is_frozen: bool
    is_venv: Callable[[], bool]
    argv: list[str]
    script_path: str
    track_docs_link_shown: Callable[[str, str], None]
    build_preflight_args: Callable[[], object]
    handle_check: Callable[[object], bool]
    get_last_check_extra: Callable[[], dict[str, object]]
    resolve_license_mode: Callable[[bool], object]
    create_shell: Callable[[object, object], object]
    console: object
    is_first_run: Callable[[], bool]
    show_first_run_helper: Callable[[Any | None], None]
    mark_first_run_complete: Callable[[], None]
    confirm_ask: Callable[[str, bool], bool]
    exit: Callable[[int], None]
    stdin_isatty: Callable[[], bool] = lambda: sys.stdin.isatty()
    get_env: Callable[[str], str | None] = staticmethod(os.getenv)
    monotonic: Callable[[], float] = staticmethod(time.monotonic)


def run_start_session(*, config: StartSessionConfig, deps: StartSessionDeps) -> None:
    """Run the legacy interactive start flow.

    This wraps the original `handle_start` implementation in `adscan.py` while
    avoiding direct imports of `PentestShell` to prevent circular dependencies.
    """
    maybe_relaunch_into_venv(
        is_frozen=deps.is_frozen,
        is_venv=deps.is_venv,
        venv_path=config.venv_path,
        tools_install_dir=config.tools_install_dir,
        argv=deps.argv,
        script_path=deps.script_path,
        track_docs_link_shown=deps.track_docs_link_shown,
    )

    if deps.is_frozen:
        print_info_verbose(
            "Running as a compiled application. Skipping venv relaunch check."
        )

    preflight_result = run_session_preflight(
        config=SessionPreflightConfig(
            command_name="start",
            docs_utm_medium="start_preflight_failed",
            allow_unsafe_override=True,
        ),
        deps=SessionPreflightDeps(
            build_preflight_args=deps.build_preflight_args,
            handle_check=deps.handle_check,
            get_last_check_extra=deps.get_last_check_extra,
            track_docs_link_shown=deps.track_docs_link_shown,
            confirm_ask=deps.confirm_ask,
            exit=deps.exit,
            stdin_isatty=deps.stdin_isatty,
            get_env=deps.get_env,
        ),
    )
    preflight_ok = preflight_result.passed
    preflight_fix_attempted = preflight_result.fix_attempted
    preflight_overridden = preflight_result.overridden

    try:
        prepend_tools_to_path(tools_install_dir=config.tools_install_dir)

        from rich.text import Text
        from adscan_internal.rich_output import BRAND_COLORS, print_panel

        welcome_text = Text(
            "\nWelcome to ADscan!\nYour Advanced Active Directory Scanner.\n",
            justify="center",
        )
        print_panel(
            welcome_text,
            title=f"[bold {BRAND_COLORS['info']}]ADscan[/bold {BRAND_COLORS['info']}]",
            subtitle="[dim]Loading...[/dim]",
            border_style=BRAND_COLORS["info"],
            padding=(1, 2),
        )

        license_mode = deps.resolve_license_mode(config.requested_pro)
        shell = deps.create_shell(deps.console, license_mode)
        setattr(shell, "session_command_type", "start")
        if not _ensure_workspace_selected_for_start(shell):
            return

        shell.preflight_check_passed = bool(preflight_ok)
        shell.preflight_check_fix_attempted = bool(preflight_fix_attempted)
        shell.preflight_check_overridden = bool(preflight_overridden)

        from adscan_internal.cli.common import build_telemetry_context

        telemetry_context = build_telemetry_context(
            shell=shell, trigger="session_start"
        )

        telemetry.set_cli_telemetry(shell.telemetry, context=telemetry_context)

        session_properties: dict[str, object] = {
            "$set": {"installation_status": "installed"}
        }
        session_properties.update(build_lab_event_fields(shell=shell, include_slug=False))
        session_properties["verbose_mode"] = config.verbose_mode
        session_properties["debug_mode"] = config.debug_mode
        session_properties["preflight_check_passed"] = bool(preflight_ok)
        session_properties["preflight_check_fix_attempted"] = bool(
            preflight_fix_attempted
        )
        session_properties["preflight_check_overridden"] = bool(preflight_overridden)
        telemetry.capture("session_start", properties=session_properties)

        shell._session_start_time = deps.monotonic()

        if should_show_workspace_getting_started(shell):
            deps.show_first_run_helper(deps.track_docs_link_shown)

        shell.run()
    except Exception as exc:  # noqa: BLE001 - preserve legacy catch-all behaviour
        telemetry.capture_exception(exc)
        print_error("An error occurred while running the shell.")
        print_exception(show_locals=False, exception=exc)
        raise


def _ensure_workspace_selected_for_start(shell: Any) -> bool:
    """Require an active workspace before entering the interactive shell.

    Startup prompts are a special case: entering the shell without a workspace
    leads to partial failures later because many commands assume workspace
    persistence exists. If the user cancels the workspace picker, we keep them
    in a small startup loop where the only valid actions are retry, create, or
    exit the `start` flow cleanly.
    """

    shell.ensure_workspaces_dir()
    if getattr(shell, "current_workspace", None):
        return True

    while not getattr(shell, "current_workspace", None):
        shell.workspace_select()
        if getattr(shell, "current_workspace", None):
            return True

        print_panel(
            "[bold]An active workspace is required before ADscan enters the interactive shell.[/bold]\n\n"
            "You cancelled the workspace selection prompt.\n\n"
            "[bold]Why this matters:[/bold]\n"
            "• scan state, credentials, and artifacts are stored in the workspace\n"
            "• domain sub-workspaces are created under the active workspace\n"
            "• continuing without one leads to partial failures later\n\n"
            "[dim]Choose one of the actions below to continue cleanly.[/dim]",
            title="[bold]Workspace Required[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )

        action_options = [
            "Retry workspace selection",
            "Create a new workspace",
            "Exit ADscan start",
        ]
        action_idx = getattr(shell, "_questionary_select")(
            "Select how to continue:",
            action_options,
        )

        if action_idx == 0:
            continue

        if action_idx == 1:
            shell.workspace_create()
            if getattr(shell, "current_workspace", None):
                return True
            print_warning("Workspace creation was cancelled. No shell session was started.")
            continue

        print_warning("Start cancelled before entering the interactive shell.")
        return False

    return True


def run_start_unauth(shell, args: str | None) -> None:
    """Start unauthenticated scan using the legacy PentestShell implementation.

    This helper mirrors :meth:`PentestShell.do_start_unauth` while keeping the
    orchestration logic in this module so that `adscan.py` can be slimmer.
    """
    while True:
        try:
            _run_start_unauth_impl(shell, args)
            return
        except (EOFError, KeyboardInterrupt):
            action = _handle_start_wizard_interrupt(
                shell,
                command_name="start_unauth",
                switch_command="start_auth",
            )
            if action == "retry":
                continue
            if action == "switch":
                run_start_auth(shell, None)
            return


def _run_start_auth_impl(shell, args: str | None) -> None:
    """Start authenticated scan using the legacy PentestShell implementation.

    This helper mirrors :meth:`PentestShell.do_start_auth` while also supporting
    a guided interactive mode when the user runs `start_auth` without arguments.
    """
    # Interactive configuration prompts
    if not shell._prompt_type_if_missing():
        return

    if not shell._prompt_interface_if_missing():
        return

    if not shell._prompt_auto_if_missing():
        return

    # Ask if user wants to clean workspace before starting scan (only if needed)
    _prompt_workspace_cleanup(shell)

    args_list = (args or "").strip().split() if args else []
    if args_list:
        if len(args_list) != 4:
            if not sys.stdin.isatty():
                print_error(
                    "You must provide: <domain> <pdc_ip> <username> <password_or_hash>."
                )
                print_info(
                    "Usage: start_auth <domain> <pdc_ip> <username> <password_or_hash>"
                )
                return
            # Interactive recovery for partial/mistyped args.
            print_warning(
                "Arguments were incomplete/invalid. Switching to guided setup..."
            )
        else:
            domain, pdc_ip, username, password = args_list
            decision = preflight_domain_pdc(
                shell,
                domain=domain,
                candidate_ip=pdc_ip,
                interactive=bool(sys.stdin.isatty()),
                mode_label="auth",
            )
            if decision.action == "use" and decision.pdc_ip:
                persist_pdc_preflight_result(shell, decision)
                domain = decision.domain
                pdc_ip = decision.pdc_ip
            elif decision.action in {"reenter", "fallback"} and sys.stdin.isatty():
                print_panel(
                    "[bold]The provided domain/DC target could not be validated.[/bold]\n\n"
                    "We'll switch to guided target selection to ensure we use the correct DC/PDC.\n",
                    title="[bold]🧭 Target Validation[/bold]",
                    border_style="yellow",
                    padding=(1, 2),
                )
                context = _domain_context_wizard_for_auth(shell)
                if context is None:
                    print_error(
                        "A valid DC/PDC target is required for authenticated scanning."
                    )
                    return
                domain, pdc_ip = context
            finalize_domain_context(
                shell,
                domain=domain,
                pdc_ip=pdc_ip,
                interactive=bool(sys.stdin.isatty()),
            )
            _start_auth_with_params(
                shell,
                domain=domain,
                pdc_ip=pdc_ip,
                username=username,
                password=password,
            )
            return

    if not sys.stdin.isatty():
        print_error("Interactive input is not available.")
        print_info("Usage: start_auth <domain> <pdc_ip> <username> <password_or_hash>")
        return

    creds = _prompt_auth_credentials_interactive(shell)
    if creds is None:
        return
    username, password = creds

    print_panel(
        "[bold]Domain Context[/bold]\n\n"
        "To verify and use the credentials, we need the target domain and a reachable DC/PDC IP.\n"
        "Provide whatever you know (domain, IP, or DC hostname) and we'll validate it.\n",
        title="[bold]🎯 Target Context[/bold]",
        border_style="blue",
        padding=(1, 2),
    )

    from rich.prompt import Confirm
    from rich.text import Text

    while True:
        context = _domain_context_wizard_for_auth(shell)
        if context is not None:
            domain, pdc_ip = context
            finalize_domain_context(
                shell,
                domain=domain,
                pdc_ip=pdc_ip,
                interactive=True,
            )
            _start_auth_with_params(
                shell,
                domain=domain,
                pdc_ip=pdc_ip,
                username=username,
                password=password,
            )
            return

        print_panel(
            "[bold]A DC/PDC target is required for authenticated scanning.[/bold]\n\n"
            "If you don't know the domain and a reachable DC IP, you can switch to\n"
            "[bold]start_unauth[/bold] to discover the domain first.\n",
            title="[bold]🧭 Missing Target Information[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
        if Confirm.ask(
            Text("Switch to start_unauth instead?", style="cyan"),
            default=False,
        ):
            run_start_unauth(shell, None)
            return
        if not Confirm.ask(
            Text("Try entering the target context again?", style="cyan"), default=True
        ):
            return


def _prompt_auth_credentials_interactive(shell: Any) -> tuple[str, str] | None:
    """Prompt for username + password/hash for an authenticated scan.

    The user must provide both fields; otherwise, they should use `start_unauth`.

    Returns:
        (username, password_or_hash) or None if cancelled.
    """
    from rich.prompt import Confirm, Prompt
    from rich.text import Text

    while True:
        print_panel(
            "[bold]Credentials Required[/bold]\n\n"
            "Authenticated scanning requires valid domain credentials.\n"
            "If you don't have credentials, use [bold]start_unauth[/bold] instead.\n\n"
            "[dim]Tip: you can paste an NTLM hash (LM:NT) as the credential value.[/dim]",
            title="[bold]🔐 Credentials[/bold]",
            border_style="cyan",
            padding=(1, 2),
        )

        username = Prompt.ask(
            Text("Enter the username (e.g., alice)", style="cyan"), default=""
        ).strip()
        if not username:
            print_warning("Username cannot be empty. Please try again.")
            continue

        password = Prompt.ask(
            Text("Enter the password or NTLM hash (visible input)", style="cyan"),
            default="",
        ).strip()
        if not password:
            print_warning("Password/hash cannot be empty. Please try again.")
            continue

        cred_type = "Hash" if shell.is_hash(password) else "Password"
        print_panel(
            "[bold]Credential Summary[/bold]\n\n"
            f"Username: {mark_sensitive(username, 'user')}\n"
            f"Credential Type: {cred_type}\n\n"
            "[dim]Credentials will be verified against the target domain.[/dim]",
            title="[bold]✅ Confirm Credentials[/bold]",
            border_style="green",
            padding=(1, 2),
        )

        if Confirm.ask(
            Text("Proceed with these credentials?", style="cyan"), default=True
        ):
            return username, password

        if not Confirm.ask(Text("Re-enter credentials?", style="cyan"), default=True):
            return None


def _maybe_apply_domain_inference(shell: Any, domain: str | None) -> None:
    """Apply domain-based lab/workspace inference to the shell when context is missing.

    Runs inference from the domain name and populates shell attributes
    (``type``, ``lab_provider``, ``lab_name``, ``lab_name_whitelisted``) only
    when they are not already explicitly set.  After updating the shell it
    persists the new values via ``save_workspace_data`` so subsequent sessions
    on the same workspace inherit the inferred context.

    This function is best-effort: any exception during inference or persistence
    is silently swallowed so that it can never block a scan.

    Args:
        shell: The PentestShell instance (or any compatible object).
        domain: Fully qualified domain name being scanned.  Inference is
            skipped when this is ``None`` or empty.
    """
    if not domain:
        print_info_debug("[domain_inference] skip: domain is empty")
        return

    # Lab context inference is meaningless for audit workspaces — skip entirely.
    if getattr(shell, "type", None) == "audit":
        print_info_debug("[domain_inference] skip: workspace type is audit")
        return

    marked_domain = mark_sensitive(domain, "domain")
    explicit_context_locked = _has_explicit_lab_context(shell)
    current_provider: str | None = (
        getattr(shell, "lab_provider", None) if explicit_context_locked else None
    )
    current_lab: str | None = (
        getattr(shell, "lab_name", None) if explicit_context_locked else None
    )

    # Explicitly selected provider+lab — nothing to infer.
    if current_provider and current_lab:
        print_info_debug(
            f"[domain_inference] skip for {marked_domain}: "
            f"context already set (provider={current_provider} lab={current_lab})"
        )
        return

    try:
        from adscan_core.domain_inference import (
            InferenceSource,
            infer_from_ctf_context,
        )

        result = infer_from_ctf_context(
            domain,
            workspace_name=getattr(shell, "current_workspace", None),
            pdc_hostname=getattr(shell, "pdc_hostname", None),
            current_lab_provider=current_provider,
            current_lab_name=current_lab,
        )
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[domain_inference] error for {marked_domain}: {exc}")
        return

    if result.source is InferenceSource.DEFAULT:
        # No confident signal — ensure workspace_type has a sane default.
        if not getattr(shell, "type", None):
            shell.type = "ctf"
        print_info_debug(
            f"[domain_inference] default fallback for {marked_domain}: "
            f"no TLD/GOAD/name/pdc/sld match — workspace_type forced to ctf"
        )
        return

    if not _apply_lab_inference_result_to_shell(shell, result):
        print_info_debug(
            f"[domain_inference] skipped weaker result for {marked_domain}: "
            f"source={result.source.value} confidence={result.confidence:.2f}"
        )
        return

    print_info_debug(
        f"[domain_inference] {result.source.value} matched for {marked_domain}: "
        f"type={getattr(shell, 'type', None)} "
        f"provider={getattr(shell, 'lab_provider', None)} "
        f"lab={getattr(shell, 'lab_name', None)} "
        f"whitelisted={getattr(shell, 'lab_name_whitelisted', None)} "
        f"confidence={result.confidence:.2f}"
    )

    # Persist updated lab context to workspace variables (best-effort).
    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()
        except Exception:  # noqa: BLE001
            pass


def _maybe_upgrade_inference_from_pdc(shell: Any, domain: str | None) -> None:
    """Upgrade lab inference metadata once PDC hostname is known.

    ``_maybe_apply_domain_inference`` fires at scan-start, before
    ``dns_find_dcs`` has resolved the PDC hostname.  This function is called
    *after* ``shell.pdc_hostname`` is populated so that
    ``infer_from_pdc_hostname`` can run with real data.

    Behaviour:
    * Explicit user-selected context is preserved.
    * Inferred context may be upgraded when the PDC-based result is stronger
      than the current inferred result.
    * Best-effort: any exception is silently swallowed so the scan is never
      interrupted.

    Args:
        shell: The PentestShell instance.
        domain: Fully qualified domain name being scanned.
    """
    if not domain:
        return
    if getattr(shell, "type", None) == "audit":
        return

    pdc_hostname: str | None = getattr(shell, "pdc_hostname", None)
    if not pdc_hostname:
        return

    try:
        from adscan_core.domain_inference import (  # noqa: PLC0415
            InferenceSource,
            infer_from_ctf_context,
        )

        explicit_context_locked = _has_explicit_lab_context(shell)

        result = infer_from_ctf_context(
            domain,
            workspace_name=getattr(shell, "current_workspace", None),
            pdc_hostname=pdc_hostname,
            current_lab_provider=(
                getattr(shell, "lab_provider", None) if explicit_context_locked else None
            ),
            current_lab_name=(
                getattr(shell, "lab_name", None) if explicit_context_locked else None
            ),
        )
        if result.source is InferenceSource.DEFAULT:
            return

        if not _apply_lab_inference_result_to_shell(shell, result):
            return
        print_info_debug(
            f"[domain_inference] pdc_hostname update: "
            f"source={result.source.value} confidence={result.confidence:.2f} "
            f"pdc_hostname={mark_sensitive(pdc_hostname, 'hostname')}"
        )
        if hasattr(shell, "save_workspace_data"):
            try:
                shell.save_workspace_data()
            except Exception:  # noqa: BLE001
                pass

    except Exception:  # noqa: BLE001
        pass


def _start_auth_with_params(
    shell: Any,
    *,
    domain: str,
    pdc_ip: str,
    username: str,
    password: str,
) -> None:
    """Run the authenticated scan flow for validated parameters."""
    _maybe_apply_domain_inference(shell, domain)
    interactive_mode = bool(sys.stdin.isatty())
    if not _run_start_network_preflight(
        shell,
        mode_label="start_auth",
        interface=getattr(shell, "interface", None),
        interactive=interactive_mode,
        target_ip=pdc_ip,
        require_dc_ports=True,
    ):
        return

    # Professional scan initialization header
    from adscan_internal import print_operation_header

    cred_type = "Hash" if shell.is_hash(password) else "Password"
    print_operation_header(
        "Starting Authenticated Scan",
        details={
            "Scan Type": "Authenticated",
            "Workspace Type": shell.type.upper() if shell.type else "N/A",
            "Domain": domain,
            "PDC IP": pdc_ip,
            "Username": username,
            "Credential Type": cred_type,
            "Auto Mode": "Enabled" if shell.auto else "Disabled",
            "Interface": shell.interface,
        },
        icon="🔐",
    )

    if not shell.do_check_dns(domain, pdc_ip):
        return

    shell.scan_mode = "auth"
    shell.domain_validated_cred_counts = {}
    shell.scan_start_time = time.monotonic()

    # Reset scan-level metrics for case studies
    # Note: Attack path metrics are computed from attack_graph.json at scan completion
    shell._scan_first_credential_time = None
    shell._scan_compromise_time = None

    properties = {
        "type": shell.type,
        "interface": shell.interface,
        "auto": shell.auto,
    }
    properties.update(build_lab_event_fields(shell=shell, include_slug=True))
    properties["preflight_check_passed"] = bool(shell.preflight_check_passed)
    properties["preflight_check_fix_attempted"] = bool(
        shell.preflight_check_fix_attempted
    )
    properties["preflight_check_overridden"] = bool(shell.preflight_check_overridden)

    if shell.current_workspace:
        import hashlib
        from adscan_internal.telemetry import TELEMETRY_ID

        workspace_unique_id = f"{TELEMETRY_ID}:{shell.current_workspace}"
        properties["workspace_id_hash"] = hashlib.sha256(
            workspace_unique_id.encode()
        ).hexdigest()[:12]

    telemetry.capture("start_auth", properties)
    print_info_debug(
        "[start_auth] verified input context prepared; authenticated enumeration "
        f"will be forced after credential validation for domain "
        f"{mark_sensitive(domain, 'domain')}"
    )
    emit_phase("credential_setup")
    print_info_verbose(
        f"Adding credential for domain {mark_sensitive(domain, 'domain')} "
        f"with PDC IP {mark_sensitive(pdc_ip, 'ip')}"
    )
    shell.add_credential(
        domain,
        username,
        password,
        pdc_ip=pdc_ip,
        force_authenticated_enumeration=True,
        prompt_when_already_authenticated=True,
    )
    mark_workspace_start_scan_completed(shell, "start_auth")
    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()
        except Exception:  # noqa: BLE001 - onboarding persistence is best effort
            pass

def run_start_auth(shell, args: str | None) -> None:
    """Start authenticated scan using the legacy PentestShell implementation.

    This helper mirrors :meth:`PentestShell.do_start_auth` while also supporting
    a guided interactive mode when the user runs `start_auth` without arguments.
    """
    while True:
        try:
            _run_start_auth_impl(shell, args)
            return
        except (EOFError, KeyboardInterrupt):
            action = _handle_start_wizard_interrupt(
                shell,
                command_name="start_auth",
                switch_command="start_unauth",
            )
            if action == "retry":
                continue
            if action == "switch":
                run_start_unauth(shell, None)
            return
