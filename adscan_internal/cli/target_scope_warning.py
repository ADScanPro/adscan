"""Reusable UX helpers for large target scope warnings."""

from __future__ import annotations

import ipaddress
from typing import Any

from rich.prompt import Confirm

from adscan_internal import print_panel, print_warning
from adscan_internal.interaction import is_non_interactive
from adscan_internal.rich_output import mark_sensitive


def estimate_target_scope_size(targets: str | list[str]) -> int | None:
    """Estimate host count for CIDR/IP target expressions.

    Non-network tokens (for example file paths) are ignored. Returns ``None``
    when no token can be parsed as an IP/CIDR expression.
    """
    if isinstance(targets, str):
        target_values = [targets]
    else:
        target_values = [str(item).strip() for item in targets if str(item).strip()]

    total = 0
    parsed_any = False
    for token in target_values:
        value = str(token or "").strip()
        if not value or value.endswith(".txt"):
            continue
        try:
            total += int(ipaddress.ip_network(value, strict=False).num_addresses)
            parsed_any = True
        except ValueError:
            continue
    return total if parsed_any else None


def confirm_large_target_scope(
    shell: Any,
    *,
    targets: list[str],
    threshold: int,
    title: str,
    context_label: str,
    recommendation_lines: list[str],
    confirm_prompt: str,
    default_confirm: bool = False,
    non_interactive_message: str | None = None,
) -> bool:
    """Warn before continuing with a very large target scope."""
    estimated_targets = estimate_target_scope_size(targets)
    if not estimated_targets or estimated_targets <= threshold:
        return True

    marked_targets = mark_sensitive(" ".join(targets[:4]), "host")
    if len(targets) > 4:
        marked_targets += f" (+{len(targets) - 4} more)"

    panel_lines = [
        "[bold]Large Target Scope Detected[/bold]",
        "",
        f"Context: {context_label}",
        f"Estimated targets: {estimated_targets}",
        f"Examples: {marked_targets}",
        "",
        *recommendation_lines,
    ]
    print_panel(
        "\n".join(panel_lines),
        title=title,
        border_style="yellow",
        expand=False,
    )

    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        response = confirmer(confirm_prompt, default=default_confirm)
        return bool(response)

    if is_non_interactive(shell):
        if non_interactive_message:
            print_warning(non_interactive_message)
        return True

    return bool(Confirm.ask(confirm_prompt, default=default_confirm))
