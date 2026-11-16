"""How the PRO licence status reaches a person or a pipeline (one place for all surfaces).

* :func:`status_document` — ``adscan license status --json``, the versioned
  ``license_status`` output format.
* :func:`banner_line` — the one line under the PRO badge of the start banner
  and the welcome screen ("PRO · licence until 1 Dec 2026 (19 days)").
* :func:`print_launch_notice` — what a launch says about the licence, by how
  close the CONTRACT end is: a quiet note at most once a day from 30 days, a
  warning on every start from 7, an urgent panel from 3 and on the last day,
  and red in grace. Non-interactive runs get the same lines once, plainly.
* :func:`render_status_panel` — ``adscan license status`` / ``show``.

The text speaks about the contract. Only a machine that cannot refresh its
document on its own (offline mode, no route to ADscan) hears about the
document, and only once its renewal date has passed (the wording comes from
:func:`adscan_core.pro_license.evaluation.evaluate_pro_license`).

The once-a-day note keeps its memory in the ADscan state directory
(``licence-notice.json``), per viewer and never in a workspace.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any

from adscan_core.pro_license import evaluation as ev
from adscan_core.pro_license.model import CONTRACT_OPEN_ENDED

NOTICE_STATE_FILENAME = "licence-notice.json"

_LEVEL_STYLE = {
    ev.NOTICE_NOTE: "dim",
    ev.NOTICE_WARNING: "yellow",
    ev.NOTICE_URGENT: "bold yellow",
    ev.NOTICE_CRITICAL: "bold red",
}


def _human(day: date) -> str:
    return f"{day.day} {day.strftime('%b %Y')}"


def _plural(days: int) -> str:
    return f"{days} day{'s' if days != 1 else ''}"


# ── JSON ──────────────────────────────────────────────────────────────────────


def status_document(
    store: Any,
    status: ev.ProLicenseStatus | None = None,
    *,
    enforced: bool | None = None,
    trusted_keys: Mapping[str, str] | None = None,
    check_in: Any = None,
) -> dict[str, Any]:
    """The ``license_status`` document (``adscan license status --json``).

    ``check_in`` is the check-in this command just made, when it made one; the
    ``licence_notice`` block (:mod:`adscan_core.pro_license.connection`) reads it.
    """
    from adscan_core.pro_license.connection import licence_notice, notice_block

    from adscan_core.pro_license.state import STATUS_PENDING, STATUS_REFUSED, STATUS_REGISTERED

    if status is None:
        status = ev.check_pro_license(store, trusted_keys=trusted_keys)
    if enforced is None:
        enforced = ev.enforcement_required(store)
    entries = store.register_entries()
    # Registered means the receipt verifies; a status with no valid receipt is
    # still to be registered, so it counts as pending.
    verified = sum(1 for code in entries if store.is_registered(code, trusted_keys=trusted_keys))
    marked = sum(1 for e in entries.values() if e.get("status") == STATUS_REGISTERED)
    installation = store.existing_installation()
    data = status.to_dict(enforced=enforced)
    data.update(
        {
            "enforcement": "required" if enforced else "dormant",
            "installation_id": installation.installation_id if installation else None,
            "domains": {
                "registered": verified,
                "pending": sum(1 for e in entries.values() if e.get("status") == STATUS_PENDING)
                + (marked - verified),
                "refused": sum(1 for e in entries.values() if e.get("status") == STATUS_REFUSED),
            },
            "queued_requests": len(store.pending()),
            "last_contact": store.last_contact(),
            "last_check_in_result": store.last_check_in().get("last_result"),
            "licence_notice": notice_block(licence_notice(store, status, check_in=check_in)),
        }
    )
    return data


# ── Banner ────────────────────────────────────────────────────────────────────


def banner_line(status: ev.ProLicenseStatus | None) -> str | None:
    """One concise line for the start banner; None when there is nothing to say.

    LITE and a dormant PRO (no licence, not required) show nothing.
    """
    if status is None or status.state == ev.STATE_NOT_REQUIRED:
        return None
    lic = status.licence
    if lic is None:
        return "PRO · no licence active"
    label = lic.label
    if status.state in (ev.STATE_REVOKED, ev.STATE_EXPIRED, ev.STATE_INVALID, ev.STATE_CLOCK_ROLLBACK):
        return f"{label} · licence inactive"
    if status.state == ev.STATE_GRACE and status.days_remaining is not None:
        return f"{label} · licence ended, new scans stop in {_plural(status.days_remaining)}"
    if lic.contract_term == CONTRACT_OPEN_ENDED:
        return f"{label} · no end date"
    if lic.contract_ends_on is not None and status.contract_days_remaining is not None:
        return f"{label} · licence until {_human(lic.contract_ends_on)} ({_plural(status.contract_days_remaining)})"
    return f"{label} · licence active"


def banner_style(status: ev.ProLicenseStatus | None) -> str:
    """Rich style for :func:`banner_line` (quiet unless the licence needs attention)."""
    if status is None:
        return "dim"
    level = status.notice_level
    if level in (ev.NOTICE_URGENT, ev.NOTICE_CRITICAL):
        return _LEVEL_STYLE[level]
    if level == ev.NOTICE_WARNING:
        return "yellow"
    return "dim"


def banner_text(license_mode: str):
    """The licence line as a Rich ``Text`` for a banner, or None (LITE, dormant, any failure).

    Local and cheap: reads the signed document, never the network.
    """
    try:
        if str(license_mode or "").upper() != "PRO":
            return None
        from rich.text import Text

        from adscan_core.pro_license.state import ProLicenseStore

        store = ProLicenseStore()
        if not ev.enforcement_required(store):
            return None
        status = ev.check_pro_license(store, session_clock=True)
        line = banner_line(status)
        if not line:
            return None
        return Text("  " + line, style=banner_style(status))
    except Exception:  # noqa: BLE001 - a banner never breaks a launch
        return None


# ── Launch notice ─────────────────────────────────────────────────────────────


def _notice_state_path(state_dir: Path | None) -> Path:
    if state_dir is None:
        from adscan_core.paths import get_state_dir

        state_dir = get_state_dir()
    return Path(state_dir) / NOTICE_STATE_FILENAME


def _note_already_shown_today(status: ev.ProLicenseStatus, today: date, state_dir: Path | None) -> bool:
    """True when today's note for this grant was already shown; records it otherwise."""
    from adscan_core.pro_license._io import read_json, write_json

    lic = status.licence
    key = f"{lic.grant_id or lic.license_id}:{'refresh' if status.refresh_notice else 'contract'}" if lic else "none"
    path = _notice_state_path(state_dir)
    data = read_json(path)
    data = dict(data) if isinstance(data, Mapping) else {}
    if data.get(key) == today.isoformat():
        return True
    data[key] = today.isoformat()
    try:
        write_json(path, data)
    except Exception:  # noqa: BLE001 - a read-only state dir shows the note every time instead
        pass
    return False


def launch_notice(
    status: ev.ProLicenseStatus | None,
    *,
    now: datetime | None = None,
    state_dir: Path | None = None,
    remember: bool = True,
) -> tuple[str, str] | None:
    """``(level, text)`` a launch should show now, or None.

    A ``note`` is shown at most once a day per grant (``remember`` records it);
    every other level is shown on every start.
    """
    if status is None or status.notice_level == ev.NOTICE_NONE:
        return None
    if status.state in (ev.STATE_NOT_REQUIRED,):
        return None
    if status.notice_level == ev.NOTICE_NOTE:
        today = (now or ev.docs.utc_now()).date()
        if remember and _note_already_shown_today(status, today, state_dir):
            return None
    return status.notice_level, status.message


def print_launch_notice(
    status: ev.ProLicenseStatus | None,
    *,
    interactive: bool,
    now: datetime | None = None,
    state_dir: Path | None = None,
) -> str | None:
    """Print the launch notice through the shared console helpers; return its level.

    Interactive: an urgent notice is a panel. Non-interactive (``adscan ci``):
    the same text once, as a plain line, never a prompt.
    """
    notice = launch_notice(status, now=now, state_dir=state_dir)
    if notice is None:
        return None
    level, text = notice
    from rich.text import Text

    from adscan_core.rich_output import print_error, print_info, print_panel, print_warning

    if level == ev.NOTICE_NOTE:
        print_info(Text(text, style="dim"))
    elif level == ev.NOTICE_WARNING:
        print_warning(Text(text))
    elif level == ev.NOTICE_URGENT:
        if interactive:
            print_panel(Text(text), title="PRO licence", border_style="yellow", padding=(0, 2))
        else:
            print_warning(Text(text))
    else:
        if interactive and status is not None and status.scans_allowed:
            print_panel(Text(text), title="PRO licence", border_style="red", padding=(0, 2))
        else:
            print_error(Text(text))
    return level


# ── Status panel ──────────────────────────────────────────────────────────────


def _row_contract(doc: Mapping[str, Any]) -> str:
    term = doc.get("contract_term")
    if term == "open_ended":
        return "No end date"
    end = doc.get("contract_ends_on")
    if end:
        days = doc.get("contract_days_remaining")
        when = _human(date.fromisoformat(end))
        if days is None:
            return when
        return f"{when} ({_plural(days)} left)" if days else f"{when} (ended)"
    return "Updated at the next check-in"


def _row_refresh(doc: Mapping[str, Any]) -> str:
    lic = doc.get("license") or {}
    if lic.get("registration_policy") == "offline":
        return "Not needed (offline engagement licence)"
    if doc.get("renews_automatically"):
        return "On (every online launch)"
    return "Off in offline mode (use `adscan license relay export`)"


def _row_instant(value: str | None) -> str:
    if not value:
        return "Never"
    try:
        moment = ev.docs.parse_instant(value)
    except ValueError:
        return value
    return f"{_human(moment.date())}, {moment.strftime('%H:%M')} UTC"


def render_status_panel(doc: Mapping[str, Any]):
    """A Rich panel for ``adscan license status`` from a :func:`status_document`."""
    from rich import box
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from adscan_core.rich_output import mark_sensitive
    from adscan_core.theme import ADSCAN_PRIMARY

    lic = doc.get("license") or {}
    level = doc.get("notice_level") or ev.NOTICE_NONE
    state = doc.get("state")
    allowed = bool(doc.get("scans_allowed"))
    border = {
        ev.NOTICE_CRITICAL: "red",
        ev.NOTICE_URGENT: "yellow",
        ev.NOTICE_WARNING: "yellow",
    }.get(level, ADSCAN_PRIMARY)
    if not allowed:
        border = "red"

    headline = Text(str(doc.get("message") or ""), style=_LEVEL_STYLE.get(level, ""))

    table = Table(box=None, show_header=False, padding=(0, 2, 0, 0), expand=False)
    table.add_column(style="dim", no_wrap=True)
    table.add_column()
    if lic:
        table.add_row("Edition", str(lic.get("edition_label") or "PRO"))
        table.add_row("Holder", mark_sensitive(str(lic.get("holder") or ""), "user"))
        if lic.get("partner_tag"):
            table.add_row("Partner", str(lic["partner_tag"]))
        table.add_row("Contract ends", _row_contract(doc))
        table.add_row("Licence refresh", _row_refresh(doc))
        table.add_row("Last refreshed", _row_instant(doc.get("last_refreshed_at")))
        notice = doc.get("licence_notice") or {}
        if notice.get("server_reached") is False:
            since = notice.get("unreachable_since")
            table.add_row(
                "Licence server",
                "Not reached" + (f" since {_row_instant(since)}" if since else ""),
            )
        offline_day = notice.get("works_offline_until")
        if offline_day:
            days = notice.get("offline_days_left")
            when = _human(date.fromisoformat(offline_day))
            table.add_row("Works offline until", f"{when} ({_plural(days)} left)" if days else when)
        elif not doc.get("renews_automatically") or doc.get("notice_level") in (ev.NOTICE_URGENT, ev.NOTICE_CRITICAL):
            # Only an offline machine needs the document date.
            if doc.get("document_valid_until"):
                table.add_row("Works offline until", _human(date.fromisoformat(doc["document_valid_until"])))
    domains = doc.get("domains") or {}
    if domains:
        line = f"{domains.get('registered', 0)} registered, {domains.get('pending', 0)} waiting"
        if domains.get("refused"):
            line += f", {domains['refused']} refused"
        table.add_row("Domains", line)
    if doc.get("installation_id"):
        table.add_row("Installation", str(doc["installation_id"]))
    for waiting in ((doc.get("licence_notice") or {}).get("pending_domains") or []):
        until = waiting.get("assessment_allowed_until")
        when = (
            f"assess until {_human(date.fromisoformat(until))} ({_plural(int(waiting.get('days_left') or 0))} left)"
            if until
            else "registered at the next contact"
        )
        table.add_row("Waiting", f"{mark_sensitive(str(waiting.get('domain_code') or ''), 'domain')}  {when}")
    queued = int(doc.get("queued_requests") or 0)
    # The table already says when the contract ends; the headline is only for
    # something the operator has to act on.
    parts: list[Any] = [headline, Text(""), table] if (level != ev.NOTICE_NONE or not allowed) else [table]
    if queued:
        parts += [
            Text(""),
            Text(
                f"{queued} request{'s' if queued != 1 else ''} waiting to be sent. They go out on the next "
                "online launch, or now with `adscan license sync`.",
                style="dim",
            ),
        ]
    title_state = "active" if allowed and state != ev.STATE_GRACE else ("grace" if allowed else "blocked")
    return Panel(
        Group(*parts),
        title=f"[bold]ADscan PRO licence[/bold] · {title_state}",
        title_align="left",
        border_style=border,
        box=box.ROUNDED,
        padding=(1, 2),
        expand=False,
    )


__all__ = [
    "NOTICE_STATE_FILENAME",
    "banner_line",
    "banner_style",
    "banner_text",
    "launch_notice",
    "print_launch_notice",
    "render_status_panel",
    "status_document",
]
