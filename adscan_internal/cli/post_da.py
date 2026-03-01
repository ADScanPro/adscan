"""Post-compromise orchestration helpers for audit workflows.

This module centralizes the post-Domain-Admin logic that refreshes BloodHound
data and re-runs attack-path analysis in audit mode.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from adscan_internal import (
    print_exception,
    print_info,
    print_panel,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive


class PostDAShell(Protocol):
    """Minimal shell interface required by post-DA helpers."""

    type: str | None
    domains_data: dict[str, object]
    license_mode: str | None

    def do_bloodhound_collector(
        self,
        target_domain: str,
        *,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> list[str]: ...

    def do_bloodhound_attack_paths(self, args: str) -> None: ...


def get_domain_post_da_state(shell: PostDAShell, domain: str) -> dict[str, object]:
    """Return mutable post-DA state bucket for a domain."""
    domain_state = shell.domains_data.setdefault(domain, {})
    if not isinstance(domain_state, dict):
        domain_state = {}
        shell.domains_data[domain] = domain_state
    post_da = domain_state.get("post_da")
    if isinstance(post_da, dict):
        return post_da
    post_da = {}
    domain_state["post_da"] = post_da
    return post_da


def _prompt_opt_in_privileged_refresh(
    *,
    shell: PostDAShell,
    domain: str,
    username: str,
) -> bool:
    """Prompt user to opt-in to optional privileged refresh in audit workflows.

    This prompt is meant to be explicit and user-friendly. It focuses on what will
    happen (extra data collection + re-analysis), the tradeoffs (time/noise), and
    that it is optional. The user's choice is persisted in the per-domain post-DA
    state to avoid re-prompting.

    Args:
        shell: Shell object holding run state.
        domain: Target domain key.
        username: Current credential label (shown as sensitive).
    Returns:
        True if user opted in, False otherwise.
    """
    from rich.prompt import Confirm

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")

    info_lines = [
        "[bold]Optional advanced phase (audit)[/bold]",
        f"Domain: {marked_domain}",
        f"Identity: {marked_user}",
        "",
        "This phase performs an additional privileged data refresh and then re-runs graph analysis.",
        "It can improve coverage/visibility for relationships and permissions discovered later in a run.",
        "",
        "[bold]Tradeoffs[/bold]",
        "- Extra runtime (one additional privileged collection cycle)",
        "- Additional directory/graph collection traffic (more noise)",
        "- Requires your BloodHound ingestion path to be configured",
        "",
        "[dim]Tip: In audit mode this is usually worth it; in time-boxed runs you may skip.[/dim]",
    ]
    print_panel(
        "\n".join(info_lines),
        title="[bold cyan]Privileged Refresh[/bold cyan]",
        border_style="cyan",
        expand=False,
    )

    proceed = bool(
        Confirm.ask(
            "Run the optional privileged refresh now?",
            default=True,
        )
    )
    return proceed


def collect_tier0_path_counts(shell: PostDAShell, domain: str) -> tuple[int, int]:
    """Return (paths_to_tier0, paths_not_attempted) from attack graph metrics."""
    try:
        from adscan_internal.services.attack_graph_service import (
            compute_attack_path_metrics,
        )

        metrics = compute_attack_path_metrics(shell, domain, max_depth=10)
        total = int(metrics.get("paths_to_tier0", 0) or 0)
        theoretical = int(metrics.get("paths_not_attempted", 0) or 0)
        return total, theoretical
    except Exception as exc:
        telemetry.capture_exception(exc)
        return 0, 0


def run_audit_post_da_bloodhound_refresh(
    shell: PostDAShell,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Refresh graph collection and rerun path analysis after DA in audit mode."""
    if shell.type != "audit":
        return

    state = get_domain_post_da_state(shell, domain)
    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")

    if not _prompt_opt_in_privileged_refresh(
        shell=shell,
        domain=domain,
        username=username,
    ):
        state["bh_da_refresh_last_opt_in"] = False
        print_info(
            f"Skipping optional privileged refresh for {marked_domain}. Continuing with remaining phases."
        )
        return

    state["bh_da_refresh_last_opt_in"] = True
    previous_total, previous_theoretical = collect_tier0_path_counts(shell, domain)
    upload_ok = True
    print_info(
        "Refreshing relationship-graph collection as "
        f"{marked_user} for {marked_domain} (single cycle)."
    )

    try:
        generated_zip_paths = shell.do_bloodhound_collector(
            domain,
            auth_username=username,
            auth_password=password,
            auth_domain=domain,
        )

        from adscan_internal.bloodhound_legacy import get_bloodhound_mode

        if get_bloodhound_mode() == "ce":
            from adscan_internal.cli.bloodhound import (
                upload_bloodhound_ce_zip_files,
            )

            upload_ok = upload_bloodhound_ce_zip_files(
                shell,
                domain,
                wait_for_manual_on_failure=False,
                zip_paths=generated_zip_paths or None,
            )
            if not upload_ok:
                print_warning(
                    "Automatic upload of refreshed graph collection ZIP files did not fully complete."
                )

        print_info("Re-running Attack Paths Discovery with refreshed data.")
        shell.do_bloodhound_attack_paths(domain)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_warning(
            "Post-DA graph refresh failed. Continuing with remaining post-compromise actions."
        )
        print_exception(show_locals=False, exception=exc)
        return

    current_total, current_theoretical = collect_tier0_path_counts(shell, domain)
    state["bh_da_refresh_done"] = True
    state["bh_da_refresh_username"] = str(username or "").strip().lower()
    state["bh_da_refresh_at"] = datetime.now(timezone.utc).isoformat()
    state["bh_da_refresh_upload_ok"] = bool(upload_ok)
    state["bh_da_refresh_runs"] = int(state.get("bh_da_refresh_runs", 0) or 0) + 1
    state["bh_da_refresh_last_paths_to_tier0_before"] = previous_total
    state["bh_da_refresh_last_theoretical_before"] = previous_theoretical
    state["bh_da_refresh_last_paths_to_tier0_after"] = current_total
    state["bh_da_refresh_last_theoretical_after"] = current_theoretical


__all__ = [
    "collect_tier0_path_counts",
    "get_domain_post_da_state",
    "run_audit_post_da_bloodhound_refresh",
]
