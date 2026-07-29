"""Premium Rich CLI presentation layer for native coerce-and-relay chains."""

from __future__ import annotations

from adscan_internal import print_info, print_success, print_warning
from adscan_internal.rich_output import mark_sensitive


def print_relay_preflight(
    *,
    technique: str,
    coerce_target: str,
    ca_host: str,
    ca_name: str,
    template: str,
    listener_host: str,
    listener_port: int,
    source: str,
    protocols: tuple[str, ...] = ("EFSR", "RPRN"),
) -> None:
    """Render a structured pre-flight panel before starting the relay chain."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from adscan_core.rich_output import get_console

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=15)
    grid.add_column(style="bold")

    grid.add_row("Technique", f"[bold cyan]{technique}[/]")
    grid.add_row("", "")
    grid.add_row("Coerce target", mark_sensitive(coerce_target, "hostname"))
    grid.add_row("Relay target", f"{mark_sensitive(ca_host, 'hostname')} — [magenta]{ca_name}[/]")
    grid.add_row("Template", f"[magenta]{template}[/]")
    grid.add_row("", "")
    grid.add_row(
        "Listener",
        f"[yellow]{source.upper()}[/] {mark_sensitive(listener_host, 'ip')}:{listener_port}",
    )
    grid.add_row("Coercion", "[dim]" + " + ".join(protocols) + "[/]")
    # SMB signing is only relevant when the relay destination is an SMB service.
    # ESC11 relays over MS-ICPR (RPC/DCOM) and ESC8 over HTTP — for those the
    # SMB signing state of the relay target is irrelevant.
    _relay_over_smb = source.lower() == "smb" and "icpr" not in technique.lower()
    if _relay_over_smb:
        grid.add_row(
            "SMB signing",
            "[yellow]⚠  relay target must have SMB signing disabled[/]",
        )

    title = Text("  NTLM Coerce-and-Relay  ", style="bold white on blue")
    panel = Panel(grid, title=title, border_style="blue", padding=(1, 2))
    get_console().print(panel)


def print_relay_listener_ready(listener_host: str, listener_port: int, source: str) -> None:
    print_info(
        f"Relay listener ready — "
        f"[yellow]{source.upper()}[/] {mark_sensitive(listener_host, 'ip')}:{listener_port}"
    )


def print_relay_coercing(target: str, protocols: tuple[str, ...]) -> None:
    print_info(
        f"Triggering coercion on {mark_sensitive(target, 'hostname')} "
        f"([dim]{' + '.join(protocols)}[/dim])…"
    )


def print_relay_captured(principal: str | None, ca_host: str, technique: str) -> None:
    principal_str = mark_sensitive(principal or "unknown principal", "user")
    print_success(
        f"Authentication captured: [bold]{principal_str}[/] — "
        f"relaying to [cyan]{mark_sensitive(ca_host, 'hostname')}[/] "
        f"[dim]({technique})[/dim]"
    )


def print_relay_cert_result(
    *,
    technique: str,
    principal: str | None,
    pfx_path: str,
    cert_serial: str | None = None,
    cert_subject: str | None = None,
    request_id: int | None = None,
    not_after: str | None = None,
) -> None:
    """Render a premium result panel for a successfully relayed certificate."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from adscan_core.rich_output import get_console

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=15)
    grid.add_column()

    grid.add_row("Status", f"[bold green]✓ ISSUED via {technique} relay[/]")
    grid.add_row("", "")
    if principal:
        grid.add_row("Principal", f"[bold red]{mark_sensitive(principal, 'user')}[/]")
    if cert_subject:
        grid.add_row("Subject", cert_subject)
    if cert_serial:
        grid.add_row("Serial", f"[cyan]{cert_serial}[/]")
    if request_id is not None:
        grid.add_row("Request ID", str(request_id))
    if not_after:
        grid.add_row("Valid until", f"[yellow]{not_after}[/]")
    grid.add_row("", "")
    grid.add_row("PFX path", mark_sensitive(pfx_path, "path"))
    grid.add_row("", "")
    grid.add_row(
        "Next step",
        "[dim]Use the PFX with PKINIT (adscan pass-the-cert) to obtain NT hash[/]",
    )
    # The certificate lives in the client's CA until it is revoked, so the
    # operator is told here that it has been recorded for the cleanup report.
    grid.add_row(
        "Cleanup",
        "[dim]Recorded as an environment change — revocation is a manual step "
        "for the client[/]",
    )

    title = Text("  Certificate Issued (Relay)  ", style="bold white on green")
    panel = Panel(grid, title=title, border_style="green", padding=(1, 2))
    get_console().print(panel)


def print_relay_not_viable(technique: str, reason: str) -> None:
    """Report that a relay technique is not viable, so no coercion was attempted.

    Used when a pre-flight probe already proved the avenue cannot yield a
    result (e.g. the CA web-enrollment endpoint is not listening). Aborting
    before coercion avoids an OPSEC-costly, EDR-visible authentication attempt
    against a target that can never complete the relay.
    """
    print_warning(f"{technique}: {reason} Coercion was not attempted.")


def print_relay_no_auth(technique: str, timed_out: bool, coercion_success: bool) -> None:
    if timed_out:
        print_warning(
            f"{technique}: relay listener timed out — no authentication was captured. "
            "Verify the listener IP is reachable from the coercion target and SMB signing is off."
        )
    elif not coercion_success:
        print_warning(
            f"{technique}: coercion did not trigger an outbound authentication. "
            "Try PetitPotam (EFSR) or PrintSpooler (RPRN) manually."
        )
    else:
        print_warning(
            f"{technique}: authentication was captured but the CA did not issue a certificate. "
            "Check the template DACL and that Web Enrollment / MS-ICPR is enabled on the CA."
        )
