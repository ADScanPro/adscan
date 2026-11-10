"""Premium Rich CLI display for native SMB privilege checking.

Aesthetic: tight information density, no decorative chrome.
Every status has an unambiguous visual identity — operators scan fast.

Layout:
  1. Preflight panel   — targets, credentials, auth mode
  2. Live matrix table — hosts × results updating in real time
  3. Summary panel     — admin count, auth failures, unreachable hosts
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence

from adscan_core.tui import LiveSession, LiveSessionConfig
from adscan_core.scan_pacing import active_pacing, component_pacing
from adscan_core.scan_pacing.pacing_runtime import active_runtime
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from adscan_internal.rich_output import (
    mark_sensitive,
    print_panel,
)
from adscan_internal.services.smb_privilege import (
    SMBPrivilegeConfig,
    SMBPrivilegeResult,
    SMBPrivilegeStatus,
    check_smb_privilege,
)

# ---------------------------------------------------------------------------
# Status cell rendering
# ---------------------------------------------------------------------------

_STATUS_CELL: dict[SMBPrivilegeStatus, tuple[str, str]] = {
    SMBPrivilegeStatus.ADMIN: ("✓ ADMIN", "bold green"),
    SMBPrivilegeStatus.NOT_ADMIN: ("✗", "dim"),
    SMBPrivilegeStatus.AUTH_FAILED: ("AUTH ERR", "bold yellow"),
    SMBPrivilegeStatus.UNREACHABLE: ("UNREACHABLE", "dim red"),
    SMBPrivilegeStatus.ERROR: ("ERROR", "red"),
}

_PENDING_CELL = ("…", "dim cyan")


def _cell(status: SMBPrivilegeStatus | None, admin_share: str | None = None) -> Text:
    if status is None:
        label, style = _PENDING_CELL
        return Text(label, style=style)
    label, style = _STATUS_CELL[status]
    text = Text(label, style=style)
    if status == SMBPrivilegeStatus.ADMIN and admin_share:
        text.append(f" [{admin_share}]", style="dim green")
    return text


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


def print_smb_privilege_preflight(
    *,
    targets: list[tuple[str, str | None]],  # (ip, hostname)
    username: str,
    domain: str,
    auth_mode: str,
    use_kerberos: bool,
) -> None:
    marked_user = mark_sensitive(username, "user")
    marked_domain = mark_sensitive(domain, "domain")
    proto = "Kerberos" if use_kerberos else "NTLM → Kerberos fallback"

    lines = [
        f"[dim]Account[/dim]        [bold]{marked_user}[/bold]@[cyan]{marked_domain}[/cyan]",
        f"[dim]Auth[/dim]           {proto}",
        f"[dim]Auth mode[/dim]      {auth_mode}",
        f"[dim]Targets[/dim]        {len(targets)} host(s)",
        "[dim]Method[/dim]         SMB tree-connect → ADMIN$ / C$",
    ]
    print_panel(
        "\n".join(lines),
        title="[bold]SMB Privilege Check[/bold]",
        border_style="cyan",
    )


# ---------------------------------------------------------------------------
# Live matrix — runs checks and renders updates in real time
# ---------------------------------------------------------------------------


async def run_privilege_check_with_display(
    configs: Sequence[SMBPrivilegeConfig],
    *,
    max_concurrency: int | None = None,
    on_result: Callable[[SMBPrivilegeResult], None] | None = None,
) -> list[SMBPrivilegeResult]:
    """Run privilege checks concurrently, rendering a live table as results arrive.

    Returns results in the same order as configs.
    """
    results: list[SMBPrivilegeResult | None] = [None] * len(configs)

    def _build_table() -> Table:
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            padding=(0, 1),
            expand=False,
        )
        table.add_column("Host", no_wrap=True, style="white")
        table.add_column("IP", style="dim", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Proto", style="dim", no_wrap=True, justify="center")

        for i, cfg in enumerate(configs):
            r = results[i]
            host_label = cfg.target_hostname or cfg.target_ip
            ip_label = cfg.target_ip if cfg.target_hostname else ""
            status_cell = _cell(r.status if r else None, r.admin_share if r else None)
            proto = (r.auth_protocol or "—") if r else "…"
            table.add_row(host_label, ip_label, status_cell, proto)

        return table

    if max_concurrency is None:
        max_concurrency = int(component_pacing(active_pacing(), "sweep.smb_privilege")["max_concurrency"])
    semaphore = active_runtime().semaphore(max_concurrency)

    async def _run_one(i: int, cfg: SMBPrivilegeConfig) -> None:
        async with semaphore:
            result = await check_smb_privilege(cfg)
            results[i] = result
            if on_result:
                on_result(result)

    tasks = [asyncio.create_task(_run_one(i, cfg)) for i, cfg in enumerate(configs)]

    # alt_screen=False: this matrix is intentionally inline — operators
    # want it to stay in the scrollback alongside the summary panel
    # printed by the caller after this function returns.
    config = LiveSessionConfig(refresh_per_second=8, alt_screen=False)
    async with LiveSession(Padding(_build_table(), (0, 0)), config=config) as session:
        while not all(t.done() for t in tasks):
            session.update(Padding(_build_table(), (0, 0)))
            await asyncio.sleep(0.12)
        session.update(Padding(_build_table(), (0, 0)))

    await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if r is not None]


# ---------------------------------------------------------------------------
# Summary panel
# ---------------------------------------------------------------------------


def print_smb_privilege_summary(
    results: list[SMBPrivilegeResult],
    *,
    username: str,
    domain: str,
) -> None:
    """Print a post-scan summary panel with counts and admin host list."""
    marked_user = mark_sensitive(username, "user")
    marked_domain = mark_sensitive(domain, "domain")

    admin_results = [r for r in results if r.is_admin]
    not_admin = [r for r in results if r.status == SMBPrivilegeStatus.NOT_ADMIN]
    auth_failed = [r for r in results if r.status == SMBPrivilegeStatus.AUTH_FAILED]
    unreachable = [r for r in results if r.status == SMBPrivilegeStatus.UNREACHABLE]

    lines: list[str] = []

    if admin_results:
        lines.append(
            f"[bold green]✓ {len(admin_results)} admin[/bold green] "
            f"host(s) for [bold]{marked_user}[/bold]@[cyan]{marked_domain}[/cyan]"
        )
        for r in admin_results:
            share = f" [{r.admin_share}]" if r.admin_share else ""
            proto = f" via {r.auth_protocol}" if r.auth_protocol else ""
            lines.append(
                f"   [green]▸[/green] {mark_sensitive(r.display_host, 'hostname')}"
                f"[dim]{share}{proto}[/dim]"
            )
    else:
        lines.append(
            f"[dim]No admin access found for [bold]{marked_user}[/bold]"
            f"@[cyan]{marked_domain}[/cyan][/dim]"
        )

    if not_admin:
        lines.append(
            f"\n[dim]✗ {len(not_admin)} host(s) authenticated — no admin privileges[/dim]"
        )
    if auth_failed:
        lines.append(f"[yellow]⚠ {len(auth_failed)} authentication failure(s)[/yellow]")
    if unreachable:
        lines.append(f"[dim red]✗ {len(unreachable)} host(s) unreachable[/dim red]")

    border = "green" if admin_results else "dim"
    print_panel(
        "\n".join(lines),
        title="[bold]SMB Privilege Results[/bold]",
        border_style=border,
    )
