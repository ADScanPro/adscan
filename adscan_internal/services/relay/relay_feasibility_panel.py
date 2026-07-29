"""Premium pre-flight panel for the NTLM-relay-to-LDAP feasibility framework.

Presentation-only. Reads a :class:`RelayFeasibility` (composed by
:func:`adscan_internal.services.relay.relay_feasibility.evaluate_relay_feasibility`)
and renders an operator-facing go/no-go panel: a compact status table (one row
per precondition with an ok / blocking / warning glyph and the observed posture
value), a concise "blockers & caveats" section that explains only the verdicts
that are not ``ok`` (with the one-line remediation), and an overall verdict
line.

No decision logic lives here -- it strictly renders verdicts decided in the
feasibility module (single source of truth). Routed through ``get_console()``
so it is auto-mirrored to telemetry; never constructs a ``Console()`` directly.
English-only; sensitive host/domain values are masked with ``mark_sensitive``.
It is a static panel -- no ``LiveSession`` needed.
"""

from __future__ import annotations

from typing import Optional

from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.relay.relay_feasibility import (
    FeasibilityVerdict,
    RelayFeasibility,
)

# Status glyph + accent color, by verdict status. Glyph carries the meaning so
# it survives a monochrome terminal (never color-alone).
_STATUS_GLYPH = {
    "ok": ("✓", "green"),         # check mark
    "blocking": ("✗", "red"),     # ballot X
    "warning": ("⚠", "yellow"),   # warning sign
}

# Human-readable check labels for the panel (the technical check_id stays in
# the module; the operator reads a phrase).
_CHECK_LABELS = {
    "ntlm_enabled": "NTLM enabled",
    "ntlmv1_or_cve1040": "NTLMv1 / CVE-2019-1040",
    "self_relay_reflection": "Self-relay reflection",
    "ldap_signing": "LDAP signing",
    "ldap_channel_binding": "LDAP channel binding",
    "ldaps_available": "LDAPS available",
    "ldap_starttls_available": "LDAP StartTLS",
    "ldap_relay_target_viable": "Relay target",
    "listener_reachable_from_victim": "Listener reachable",
    "adcs_pki_present": "ADCS / PKI present",
    "machine_account_quota": "MachineAccountQuota",
    "relayed_principal_self_write": "Self-write permission",
    "smb_signing_source": "SMB signing",
    "posture_confidence_low": "Posture confidence",
}


def _label_for(verdict: FeasibilityVerdict) -> str:
    return _CHECK_LABELS.get(verdict.check_id, verdict.check_id)


def print_relay_feasibility_panel(
    feasibility: RelayFeasibility,
    *,
    domain: Optional[str] = None,
    dc_host: Optional[str] = None,
    method: Optional[str] = None,
) -> None:
    """Render the pre-flight feasibility panel for an NTLM-relay-to-LDAP attack.

    Args:
        feasibility: The composed feasibility outcome to render.
        domain: Target domain name (masked).
        dc_host: DC host / IP for the header (masked).
        method: Selected write method label (``"rbcd"`` / ``"shadow_creds"``),
            shown in the header when provided.
    """
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from adscan_core.rich_output import get_console

    border = "green" if feasibility.viable else "red"

    body = Table.grid(expand=True)
    body.add_column(ratio=1)

    # 1. Header context (target + method), masked.
    context = Table.grid(padding=(0, 2), expand=False)
    context.add_column(style="dim", justify="right", min_width=8)
    context.add_column(style="bold")
    if domain:
        context.add_row("Domain", mark_sensitive(domain, "domain"))
    if dc_host:
        context.add_row("DC", mark_sensitive(dc_host, "hostname"))
    if method:
        pretty_method = {"rbcd": "RBCD", "shadow_creds": "Shadow Credentials"}.get(
            method, method
        )
        context.add_row("Method", f"[magenta]{pretty_method}[/]")
    if context.row_count:
        body.add_row(context)
        body.add_row("")

    # 2. Compact status table: glyph | check | observed. Detail goes below so
    #    this stays dense and scannable instead of a 4-column wrap.
    status = Table.grid(padding=(0, 2), expand=False)
    status.add_column(justify="center", width=1)            # glyph
    status.add_column(style="bold", no_wrap=True)           # check label
    status.add_column(style="cyan", no_wrap=True)           # observed value

    for verdict in feasibility.verdicts:
        glyph, color = _STATUS_GLYPH.get(verdict.status, ("?", "white"))
        status.add_row(
            f"[{color}]{glyph}[/]",
            _label_for(verdict),
            verdict.observed,
        )
    body.add_row(status)

    # 3. Blockers & caveats: explain only the verdicts that aren't ok, with the
    #    one-line remediation. This is where the "why" earns the vertical space.
    non_ok = [v for v in feasibility.verdicts if v.status != "ok"]
    if non_ok:
        body.add_row("")
        body.add_row(Text("Blockers & caveats", style="bold dim"))
        notes = Table.grid(padding=(0, 1), expand=True)
        notes.add_column(justify="center", width=1)
        notes.add_column(ratio=1)
        for verdict in non_ok:
            glyph, color = _STATUS_GLYPH.get(verdict.status, ("?", "white"))
            detail = verdict.why
            if verdict.remediation:
                detail = f"{detail} [italic]Fix: {verdict.remediation}[/]"
            notes.add_row(
                f"[{color}]{glyph}[/]",
                Text.from_markup(
                    f"[bold]{_label_for(verdict)}[/] [dim]{detail}[/]"
                ),
            )
        body.add_row(notes)

    # 4. Overall verdict line.
    body.add_row("")
    if feasibility.viable:
        body.add_row(
            Text.from_markup(f"[bold green]✓ {feasibility.summary}[/]")
        )
        title_text = "  Relay Feasibility — GO  "
        title_style = "bold white on green"
    else:
        body.add_row(
            Text.from_markup(f"[bold red]✗ {feasibility.summary}[/]")
        )
        title_text = "  Relay Feasibility — NO-GO  "
        title_style = "bold white on red"

    panel = Panel(
        body,
        title=Text(title_text, style=title_style),
        border_style=border,
        padding=(1, 2),
    )
    get_console().print(panel)
