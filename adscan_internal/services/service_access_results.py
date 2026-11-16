"""Reusable service-access result normalization and follow-up UX helpers."""

from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
from typing import Any, Literal

from adscan_internal import print_info, print_info_debug, print_info_table, print_panel
from adscan_internal.rich_output import mark_sensitive


ServiceAccessCategory = Literal[
    "confirmed",
    "denied",
    "transport",
    "ambiguous",
]


@dataclass(frozen=True)
class ServiceAccessFinding:
    """Normalized post-auth service-access result independent of backend."""

    service: str
    host: str
    username: str
    category: ServiceAccessCategory
    reason: str
    status: str
    backend: str

    @property
    def is_confirmed(self) -> bool:
        """Return whether the finding confirms usable service access."""
        return self.category == "confirmed"


def summarize_service_access_categories(
    findings: list[ServiceAccessFinding],
) -> dict[str, int]:
    """Return aggregate counts per service-access category."""
    return {
        "confirmed": sum(1 for finding in findings if finding.category == "confirmed"),
        "denied": sum(1 for finding in findings if finding.category == "denied"),
        "transport": sum(1 for finding in findings if finding.category == "transport"),
        "ambiguous": sum(1 for finding in findings if finding.category == "ambiguous"),
    }


def print_service_access_summary(
    *, service: str, findings: list[ServiceAccessFinding]
) -> None:
    """Render a concise reusable summary for service access results."""
    category_counts = summarize_service_access_categories(findings)
    print_info(
        f"{service.upper()} access summary: "
        f"confirmed={category_counts['confirmed']} "
        f"denied={category_counts['denied']} "
        f"transport={category_counts['transport']} "
        f"ambiguous={category_counts['ambiguous']}"
    )


def render_service_access_results(
    *,
    service: str,
    username: str,
    findings: list[ServiceAccessFinding],
    total_targets: int | None = None,
    not_checked: int = 0,
) -> None:
    """Render a premium summary and table for service-access results.

    ``not_checked`` is the number of hosts a stop left unchecked: they are
    stated as not checked, never folded into "unconfirmed".
    """
    confirmed_findings = [
        finding for finding in findings if finding.category == "confirmed"
    ]
    category_counts = summarize_service_access_categories(findings)
    confirmed = category_counts["confirmed"]
    denied = category_counts["denied"]
    transport = category_counts["transport"]
    ambiguous = category_counts["ambiguous"]
    unconfirmed = denied + transport + ambiguous

    marked_user = mark_sensitive(username, "user")
    summary_lines = [
        f"[bold]{service.upper()} access results for {marked_user}[/bold]",
    ]
    if total_targets is not None:
        summary_lines.append(f"Targets tested: {total_targets}")
    if not_checked:
        summary_lines.append(f"Not checked (sweep stopped): {not_checked}")
    summary_lines.append(f"Confirmed access: {confirmed}")
    summary_lines.append(f"Unconfirmed: {unconfirmed}")

    if confirmed_findings:
        print_panel(
            "\n".join(summary_lines),
            title=f"[bold cyan]{service.upper()} Access Summary[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
        table_rows = [
            {
                "Host": mark_sensitive(finding.host, "hostname"),
                "Service": mark_sensitive(service.upper(), "detail"),
                "Access": "Confirmed",
                "Backend": mark_sensitive(finding.backend, "detail"),
            }
            for finding in sorted(
                confirmed_findings,
                key=lambda finding: finding.host.lower(),
            )
        ]
        print_info_table(
            table_rows,
            ["Host", "Service", "Access", "Backend"],
            title=f"{service.upper()} Confirmed Access Targets",
        )
        return

    if unconfirmed > 0:
        detail_parts: list[str] = []
        if denied:
            detail_parts.append(f"denied={denied}")
        if transport:
            detail_parts.append(f"transport={transport}")
        if ambiguous:
            detail_parts.append(f"ambiguous={ambiguous}")
        summary_lines.append(
            "Most common unconfirmed reasons: " + ", ".join(detail_parts)
        )
        reason_counter = Counter(
            (finding.reason or "").strip() or finding.category
            for finding in findings
            if finding.category != "confirmed"
        )
        if reason_counter:
            top_reasons = [
                f"{reason}={count}" for reason, count in reason_counter.most_common(3)
            ]
            summary_lines.append("Top failure details: " + ", ".join(top_reasons))

    print_panel(
        "\n".join(summary_lines),
        title=f"[bold yellow]No Confirmed {service.upper()} Access[/bold yellow]",
        border_style="yellow",
        expand=False,
    )


def render_no_confirmed_service_access(
    *,
    service: str,
    username: str,
    total_targets: int | None = None,
    not_checked: int = 0,
) -> None:
    """Render the empty-result UX for services without normalized unconfirmed findings."""
    marked_user = mark_sensitive(username, "user")
    summary_lines = [
        f"[bold]{service.upper()} access results for {marked_user}[/bold]",
    ]
    if total_targets is not None:
        summary_lines.append(f"Targets tested: {total_targets}")
    if not_checked:
        summary_lines.append(f"Not checked (sweep stopped): {not_checked}")
    summary_lines.append("Confirmed access: 0")
    summary_lines.append("No hosts returned a confirmed privileged session.")

    print_panel(
        "\n".join(summary_lines),
        title=f"[bold yellow]No Confirmed {service.upper()} Access[/bold yellow]",
        border_style="yellow",
        expand=False,
    )


def select_confirmed_service_access_followup_targets(
    shell: Any,
    *,
    service: str,
    findings: list[ServiceAccessFinding],
) -> tuple[list[ServiceAccessFinding], bool]:
    """Optionally let the user choose which confirmed hosts to follow up on.

    Returns the selected confirmed findings and whether an interactive selector
    was shown.
    """
    confirmed_findings = [finding for finding in findings if finding.is_confirmed]
    if len(confirmed_findings) <= 1:
        return confirmed_findings, False
    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive(shell):
        return confirmed_findings, False

    selector = getattr(shell, "_questionary_checkbox", None)
    if not callable(selector):
        return confirmed_findings, False

    options = [finding.host for finding in confirmed_findings]
    selected_hosts = selector(
        f"Select confirmed {service.upper()} hosts to access:",
        options,
        default_values=options,
    )
    if selected_hosts is None:
        print_info_debug(
            f"[service-access] follow-up selector cancelled for {service.upper()}"
        )
        return [], True

    selected_set = {str(host).strip().lower() for host in selected_hosts}
    selected_findings = [
        finding
        for finding in confirmed_findings
        if finding.host.strip().lower() in selected_set
    ]
    marked_hosts = [
        mark_sensitive(finding.host, "hostname") for finding in selected_findings
    ]
    print_info_debug(
        f"[service-access] selected {len(selected_findings)} {service.upper()} follow-up target(s): {marked_hosts}"
    )
    return selected_findings, True
