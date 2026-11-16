"""What an online PRO licence needs from the licence server, and how long it can go without it.

One derivation, :func:`licence_notice`, read by every surface so they cannot
disagree: the launch notice of ``adscan start``, ``ci``, ``execute`` and
``recheck``, the ``licence_notice`` block of ``adscan license status --json`` and
``adscan license check --json``, and the ``licence_notice`` event a run writes
to its event stream for an integrator's platform.

Two clocks run only while the server cannot be reached (spec § 6):

* **per domain code**, the registration grace: a domain first assessed while the
  server was out of reach may be assessed until its own ``first_seen`` plus the
  licence's grace (:func:`adscan_core.pro_license.evaluation.registration_grace_until`).
  A registered domain never needs the server again.
* **per machine**, the licence document: new assessments can start without the
  server until the document's end plus its grace
  (:func:`adscan_core.pro_license.evaluation.offline_until`).

The notice never blocks anything. It states what failed, both clocks with their
dates and days left, the domains waiting, and what to do.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from adscan_core.pro_license import documents as docs
from adscan_core.pro_license import evaluation as ev
from adscan_core.pro_license.model import POLICY_DEFERRED, ProLicense
from adscan_core.pro_license.state import (
    CHECK_IN_UNREACHABLE_RESULT,
    STATUS_PENDING,
    STATUS_REFUSED,
    STATUS_REGISTERED,
    ProLicenseStore,
)

#: Check-in outcomes that mean the server answered.
_ANSWERED = frozenset({"current", "refreshed", "notice", "revoked", "rejected"})
_LEVEL_ORDER = (ev.NOTICE_NONE, ev.NOTICE_NOTE, ev.NOTICE_WARNING, ev.NOTICE_URGENT, ev.NOTICE_CRITICAL)

#: Most waiting domains a terminal notice lists by name (the JSON carries them all).
TERMINAL_DOMAIN_LIMIT = 5


def _days_left(until: datetime, now: datetime) -> int:
    return max(0, math.ceil((until - now).total_seconds() / 86400))


def _level_for_days(days: int) -> str:
    if days <= 0:
        return ev.NOTICE_CRITICAL
    if days <= ev.URGENT_DAYS:
        return ev.NOTICE_URGENT
    if days <= ev.WARNING_DAYS:
        return ev.NOTICE_WARNING
    return ev.NOTICE_NOTE


def _louder(a: str, b: str) -> str:
    return a if _LEVEL_ORDER.index(a) >= _LEVEL_ORDER.index(b) else b


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return docs.parse_instant(value)
    except ValueError:
        return None


@dataclass(frozen=True)
class WaitingDomain:
    """A domain code assessed under this licence and not registered yet."""

    domain_code: str
    first_seen: datetime | None
    #: Last instant (exclusive) a new assessment of it may start; None when it never blocks (deferred).
    allowed_until: datetime | None
    days_left: int | None
    #: The server refused an earlier request for it only because this machine's clock was off.
    clock_refused: bool = False

    @property
    def last_day(self) -> date | None:
        """The last calendar day its assessment may continue (what a person is told)."""
        return self.allowed_until.date() if self.allowed_until is not None else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain_code": self.domain_code,
            "first_seen": docs.format_instant(self.first_seen) if self.first_seen else None,
            "assessment_allowed_until": self.last_day.isoformat() if self.last_day else None,
            "days_left": self.days_left,
        }


@dataclass(frozen=True)
class LicenceNotice:
    """The licence facts a launch, a status and a run's event stream share."""

    level: str
    #: True / False: whether the licence server answered the latest check-in
    #: (this launch's when one ran); None when no check-in is on record.
    server_reached: bool | None
    check_in_result: str | None
    #: Why the latest check-in failed, as the transport reported it.
    failure: str
    last_contact: datetime | None
    unreachable_since: datetime | None
    #: First instant new assessments can no longer start without the server.
    offline_until: datetime | None
    offline_days_left: int | None
    contract_ends_on: date | None
    contract_days_left: int | None
    contract_expiring: bool
    registered: int
    waiting: tuple[WaitingDomain, ...] = field(default_factory=tuple)

    @property
    def offline_last_day(self) -> date | None:
        return (self.offline_until - timedelta(days=1)).date() if self.offline_until else None

    @property
    def relevant(self) -> bool:
        """True when there is something to tell: the server not reached, a domain waiting, an end near.

        False when the server answered and nothing is pending or expiring, the
        case where the run output carries no block at all.
        """
        return self.server_reached is False or bool(self.waiting) or self.contract_expiring

    def to_dict(self) -> dict[str, Any]:
        """The ``licence_notice`` block (``license_status`` 1.1, the ``licence_notice`` event)."""
        return {
            "level": self.level,
            "server_reached": self.server_reached,
            "check_in_result": self.check_in_result,
            "last_contact": docs.format_instant(self.last_contact) if self.last_contact else None,
            "unreachable_since": docs.format_instant(self.unreachable_since) if self.unreachable_since else None,
            "works_offline_until": self.offline_last_day.isoformat() if self.offline_last_day else None,
            "offline_days_left": self.offline_days_left,
            "contract_ends_on": self.contract_ends_on.isoformat() if self.contract_ends_on else None,
            "contract_days_left": self.contract_days_left,
            "registered_domains": self.registered,
            "pending_domains": [d.to_dict() for d in self.waiting],
        }


def _waiting_domains(store: ProLicenseStore, licence: ProLicense, now: datetime) -> tuple[list[WaitingDomain], int]:
    registered = 0
    waiting: list[WaitingDomain] = []
    for code, entry in sorted(store.register_entries().items()):
        status = entry.get("status")
        if status == STATUS_REGISTERED:
            registered += 1
            continue
        clock_refused = status == STATUS_REFUSED and entry.get("refusal") == docs.NOTICE_STALE
        if status != STATUS_PENDING and not clock_refused:
            continue
        first_seen = _instant(store.first_seen(code))
        if licence.registration_policy == POLICY_DEFERRED or first_seen is None:
            waiting.append(WaitingDomain(code, first_seen, None, None, clock_refused))
            continue
        until = ev.registration_grace_until(licence, first_seen)
        waiting.append(WaitingDomain(code, first_seen, until, _days_left(until, now), clock_refused))
    waiting.sort(key=lambda d: (d.allowed_until is None, d.allowed_until or now, d.domain_code))
    return waiting, registered


def licence_notice(
    store: ProLicenseStore,
    status: ev.ProLicenseStatus,
    *,
    check_in: Any = None,
    now: datetime | None = None,
) -> LicenceNotice | None:
    """The notice for this machine's licence, or None when the licence never uses the server.

    ``check_in`` is this launch's :class:`adscan_core.pro_license.client.CheckInResult`
    (or its outcome string). Without it the latest recorded check-in is used.
    Local only: reads the licence directory, never the network.
    """
    licence = status.licence
    if licence is None or not licence.needs_server:
        return None
    current = now or docs.utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    record = store.last_check_in()
    outcome = getattr(check_in, "outcome", check_in)
    failure = str(getattr(check_in, "message", "") or "") if check_in is not None else ""
    if outcome is None:
        outcome = record.get("last_result")
        failure = str(record.get("last_error") or "")
    if outcome == CHECK_IN_UNREACHABLE_RESULT:
        reached: bool | None = False
    elif outcome in _ANSWERED:
        reached = True
    else:
        reached = None
    unreachable_since = _instant(record.get("unreachable_since")) if reached is False else None
    if reached is False and unreachable_since is None:
        unreachable_since = current

    stop = ev.offline_until(licence)
    offline_days = _days_left(stop, current)
    waiting, registered = _waiting_domains(store, licence, current)

    warn_window = ev.TRIAL_WARN_DAYS if licence.edition == "pro_trial" else ev.WARN_DAYS
    contract_days = status.contract_days_remaining
    contract_expiring = contract_days is not None and contract_days <= warn_window

    level = ev.NOTICE_NONE
    if reached is False:
        level = _louder(level, _level_for_days(offline_days))
    for domain in waiting:
        if domain.days_left is not None:
            level = _louder(level, _level_for_days(domain.days_left))
        else:
            level = _louder(level, ev.NOTICE_NOTE)
    if contract_expiring or not status.scans_allowed:
        level = _louder(level, status.notice_level)
    return LicenceNotice(
        level=level,
        server_reached=reached,
        check_in_result=str(outcome) if outcome else None,
        failure=failure,
        last_contact=_instant(store.last_contact()),
        unreachable_since=unreachable_since,
        offline_until=stop,
        offline_days_left=offline_days,
        contract_ends_on=licence.contract_ends_on,
        contract_days_left=contract_days,
        contract_expiring=contract_expiring,
        registered=registered,
        waiting=tuple(waiting),
    )


def notice_block(notice: LicenceNotice | None) -> dict[str, Any] | None:
    """The block a document carries: present only when :attr:`LicenceNotice.relevant`."""
    if notice is None or not notice.relevant:
        return None
    return notice.to_dict()


# ── Terminal ──────────────────────────────────────────────────────────────────


def human_date(day: date) -> str:
    """``13 Nov 2026``: how every licence surface writes a day."""
    return f"{day.day} {day.strftime('%b %Y')}"


_human = human_date


def _when(moment: datetime) -> str:
    return f"{_human(moment.date())} at {moment.strftime('%H:%M')} UTC"


def _plural(days: int) -> str:
    return f"{days} day{'s' if days != 1 else ''}"


def _left(days: int | None) -> str:
    if days is None:
        return ""
    return "ended" if days <= 0 else f"{_plural(days)} left"


def terminal_lines(notice: LicenceNotice) -> list[tuple[str, str]]:
    """``(role, text)`` lines of the launch notice; roles: lead, body, domain, action, contact, blank.

    Plain text, never Rich markup: a transport error can carry square brackets.
    Domain codes are returned raw; the renderer marks them sensitive.
    """
    lines: list[tuple[str, str]] = []
    if notice.server_reached is False:
        reason = f" ({notice.failure})" if notice.failure else ""
        lines.append(("lead", f"ADscan could not reach the licence server at this launch{reason}."))
        if notice.last_contact is not None:
            lines.append(("body", f"The last successful contact was on {_when(notice.last_contact)}."))
        else:
            lines.append(("body", "This machine has not reached the licence server since it was activated."))
        if notice.offline_last_day is not None:
            lines.append(("blank", ""))
            lines.append(
                (
                    "body",
                    f"Without it, new assessments can start on this machine until "
                    f"{_human(notice.offline_last_day)} ({_left(notice.offline_days_left)}).",
                )
            )
    elif notice.waiting:
        count = len(notice.waiting)
        lines.append(
            (
                "lead",
                f"{count} domain{'s are' if count != 1 else ' is'} still waiting to be registered "
                "with the ADscan licence server.",
            )
        )
    if notice.waiting:
        if notice.server_reached is False:
            lines.append(("blank", ""))
            lines.append(("body", "Domains waiting to be registered, and the last day each can be assessed"))
        for domain in notice.waiting[:TERMINAL_DOMAIN_LIMIT]:
            if domain.last_day is None:
                when = "registered at the next contact, never blocked"
            else:
                when = f"until {_human(domain.last_day)} ({_left(domain.days_left)})"
            lines.append(("domain", f"{domain.domain_code}\t{when}"))
        extra = len(notice.waiting) - TERMINAL_DOMAIN_LIMIT
        if extra > 0:
            lines.append(("body", f"and {extra} more (`adscan license status` lists them all)."))
        lines.append(("body", "Domains already registered are not affected."))
    elif notice.server_reached is False:
        lines.append(("body", "No domain is waiting to be registered. Domains already registered are not affected."))
    lines.append(("blank", ""))
    if notice.server_reached is False or notice.waiting:
        lines.append(
            (
                "action",
                "Run `adscan license check` to see what blocks the connection and send what is waiting. "
                "On a network with no route to ADscan, use `adscan license relay export`.",
            )
        )
    lines.append(("contact", f"Need help? Write to {ev.licence_contact_email()}."))
    return lines


def terminal_title(notice: LicenceNotice) -> str:
    if notice.server_reached is False:
        return "Licence server not reached"
    return "Domains waiting to be registered"


def shows_at_launch(notice: LicenceNotice | None) -> bool:
    """True when a launch prints the notice: the server not reached, or a domain waiting.

    A contract that is ending has its own launch notice
    (:func:`adscan_core.pro_license.status_view.print_launch_notice`).
    """
    return notice is not None and (notice.server_reached is False or bool(notice.waiting))


_PANEL_BORDER = {
    ev.NOTICE_NOTE: "cyan",
    ev.NOTICE_WARNING: "yellow",
    ev.NOTICE_URGENT: "bold yellow",
    ev.NOTICE_CRITICAL: "red",
}


def render_panel(notice: LicenceNotice):
    """The interactive launch notice as a Rich panel (also used by the 80-column render test)."""
    from rich import box
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from adscan_core.rich_output import mark_sensitive

    parts: list[Any] = []
    domains: Table | None = None
    for role, text in terminal_lines(notice):
        if role == "domain":
            if domains is None:
                domains = Table.grid(padding=(0, 2))
                domains.add_column(no_wrap=True)
                domains.add_column()
                parts.append(domains)
            code, when = text.split("\t", 1)
            domains.add_row(Text("  " + mark_sensitive(code, "domain")), Text(when))
            continue
        domains = None
        if role == "blank":
            parts.append(Text(""))
        elif role == "lead":
            parts.append(Text(text, style="bold"))
        elif role == "contact":
            parts.append(Text(text, style="dim"))
        else:
            parts.append(Text(text))
    return Panel(
        Group(*parts),
        title=f"[bold]{terminal_title(notice)}[/bold]",
        title_align="left",
        border_style=_PANEL_BORDER.get(notice.level, "cyan"),
        box=box.ROUNDED,
        padding=(0, 2),
        expand=False,
    )


def print_notice(notice: LicenceNotice | None, *, interactive: bool) -> bool:
    """Print the launch notice through the shared console helpers. True when printed. Never raises."""
    if not shows_at_launch(notice):
        return False
    assert notice is not None
    try:
        from rich.text import Text

        from adscan_core.rich_output import mark_sensitive, print_error, print_info, print_warning

        if interactive:
            from adscan_core.output._state import get_console

            get_console().print(render_panel(notice))
            return True
        loud = print_error if notice.level == ev.NOTICE_CRITICAL else (
            print_info if notice.level == ev.NOTICE_NOTE else print_warning
        )
        first = True
        for role, text in terminal_lines(notice):
            if role == "blank":
                continue
            if role == "domain":
                code, when = text.split("\t", 1)
                text = f"  {mark_sensitive(code, 'domain')}  {when}"
            (loud if first else print_info)(Text(text))
            first = False
        return True
    except Exception:  # noqa: BLE001 - a notice never breaks a launch
        return False


__all__ = [
    "LicenceNotice",
    "human_date",
    "TERMINAL_DOMAIN_LIMIT",
    "WaitingDomain",
    "licence_notice",
    "notice_block",
    "print_notice",
    "render_panel",
    "shows_at_launch",
    "terminal_lines",
    "terminal_title",
]
