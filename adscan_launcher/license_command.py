"""``adscan license``: activate, inspect and release this machine's PRO licence.

A launcher (host) command, available in every launcher, LITE included
(spec § 8): activation must work before a PRO image is on the host, and it is
the route INTO PRO, so gating it behind PRO would make PRO unreachable. It
starts no assessment and touches no directory, so the "LITE is
interactive-only" rule for scan entry points does not apply to it.

The state lives in the licence directory under the ADscan state dir, which the
launcher bind-mounts into the engine container: what this command writes is
what the engine reads.

The activation key is a secret. It is read from a file, stdin, the
``ADSCAN_ACTIVATION_KEY`` environment variable (never forwarded into the
container) or a masked prompt; never from a command-line argument, which would
land in the process list and the shell history.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

from adscan_core.rich_output import (
    mark_sensitive,
    print_error,
    print_info,
    print_success,
    print_warning,
)

ACTIVATION_KEY_ENV = "ADSCAN_ACTIVATION_KEY"

_RELAY_HELP = (
    "Relay mode is for an engine with no route to ADscan. `relay export` writes every queued "
    "request (activation, renewal, new domains) to one JSON file. Your platform posts that file "
    "unchanged to the licence server's /v1/relay endpoint and saves the answer, and `relay import` "
    "loads it. The engine accepts only answers signed by ADscan. A file holding an activation "
    "request contains the activation key, so treat it as a secret."
)


def add_license_subparser(sub: Any) -> None:
    """Register ``adscan license`` and its subcommands on the launcher parser."""
    # Listed in `adscan --help` exactly when the release ships a licence trust
    # anchor (scripts/check_pro_license_anchors.py checks both together).
    lic = sub.add_parser(
        "license",
        help="Activate and manage the ADscan PRO licence.",
        description=(
            "Activate the ADscan PRO licence once, with the activation key from your onboarding "
            "email. After that the licence is checked on this machine, and every online launch "
            "checks in with the licence server (about two seconds at most, never blocking a scan) so "
            "an extension or a change reaches this machine on its own. The check-in sends only the "
            "installation id and public key, the licence id, a request id, a sequence number, the "
            "time and the engine version, and never any scan data. Offline mode (--offline, ADSCAN_OFFLINE=1) "
            "does not turn off the licence check-in or domain registration: they send only licence "
            "identifiers, the keyed domain code and its size band, never client data. A partner licence "
            "also sends, for each run, how many accounts, computers (by server or workstation, and by the "
            "tier their membership or role gives them), domain controllers and certificate authorities it "
            "counted, never a name, an address or a finding. An offline engagement "
            "licence never connects. "
            + _RELAY_HELP
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    lsub = lic.add_subparsers(dest="license_command", metavar="subcommand", required=True)

    act = lsub.add_parser(
        "activate",
        help="Activate this machine (once) and offer the ADscan PRO download.",
    )
    act.add_argument(
        "key",
        nargs="?",
        default=None,
        help="The activation key. Accepted for convenience; --key-file or --key-stdin keep it out of "
        "your shell history.",
    )
    src = act.add_mutually_exclusive_group()
    src.add_argument("--key-file", help="Read the activation key from this file.")
    src.add_argument("--key-stdin", action="store_true", help="Read the activation key from standard input.")
    add_pull_choice_arguments(act)
    act.add_argument("--seat-label", help="A name for this seat, shown to your account (no hostname is sent).")
    act.add_argument(
        "--relay-out",
        metavar="FILE",
        help="Do not connect. Write the activation request to FILE for your platform to forward.",
    )

    for name, aliases in (("status", ["show"]),):
        st = lsub.add_parser(
            name,
            aliases=aliases,
            help="Show the licence, when the contract ends and the domains waiting to be registered.",
        )
        st.add_argument("--json", action="store_true", help="Machine-readable output (versioned).")
        st.add_argument(
            "--no-check-in",
            action="store_true",
            help="Do not check in with the licence server first (the local state only).",
        )

    de = lsub.add_parser("deactivate", help="Release this machine's seat and remove its licence.")
    de.add_argument("--relay-out", metavar="FILE", help="Write the release request to FILE instead of connecting.")

    lsub.add_parser(
        "renew",
        help="Fetch a fresh licence document now (only needed when this machine cannot reach "
        "ADscan on its own launches).",
    )
    lsub.add_parser("sync", help="Send every queued request (new domains, band updates, renewal) now.")

    chk = lsub.add_parser(
        "check",
        help="Find what blocks the connection to the licence server, then send what is waiting.",
        description=(
            "Tests the route to the ADscan licence server step by step (proxy, DNS, TCP 443, TLS, the "
            "server's health endpoint, and this machine's clock against the server's) and names the step "
            "that fails. When the server answers, it then does what `sync` and `renew` do: sends every "
            "queued request and asks for a fresh licence document. Exit code 0 when the licence server "
            "answered, 1 when it did not."
        ),
    )
    chk.add_argument("--json", action="store_true", help="Machine-readable output (versioned).")

    relay = lsub.add_parser("relay", help="Exchange requests and answers through a file (no direct route).")
    rsub = relay.add_subparsers(dest="relay_command", metavar="direction", required=True)
    rexp = rsub.add_parser("export", help="Write every queued request to a file ('-' for stdout).")
    rexp.add_argument("--out", required=True, metavar="FILE")
    rimp = rsub.add_parser("import", help="Load the licence server's answers from a file ('-' for stdin).")
    rimp.add_argument("--in", dest="in_file", required=True, metavar="FILE")

    reg = lsub.add_parser("register", help="The local register of domain codes, for reconciliation.")
    regsub = reg.add_subparsers(dest="register_command", metavar="action", required=True)
    rex = regsub.add_parser("export", help="Export the register ('-' for stdout).")
    rex.add_argument("--out", default="-", metavar="FILE")
    rex.add_argument("--format", choices=["json", "csv"], default="json")
    rex.add_argument(
        "--rows",
        choices=["codes", "engagements", "assessments"],
        default="codes",
        help="CSV only: one row per domain code (default), per billable engagement, or per assessment "
        "(full scans and rechecks).",
    )

    ins = lsub.add_parser("install", help="Install an offline engagement licence file.")
    ins.add_argument("file", metavar="FILE")


# ── Helpers ──────────────────────────────────────────────────────────────────


def _store():
    from adscan_core.pro_license.state import ProLicenseStore

    return ProLicenseStore()


def _transport():
    from adscan_core.pro_license.client import HttpTransport

    return HttpTransport()


def _offline() -> bool:
    """Offline mode with no licence to open the channel (activation, or nothing installed)."""
    from adscan_core.offline import offline_mode_enabled

    return offline_mode_enabled()


def _channel_closed(store: Any) -> bool:
    """True when offline mode keeps this machine's licence channel closed (:mod:`.channel` SSOT).

    An online licence (trial, partner, paid) connects even under offline mode,
    so ``sync``, ``renew`` and ``deactivate`` still work; the first contact
    prints one line saying so.
    """
    from adscan_core.pro_license.channel import licence_channel_offline, note_offline_contact

    licence, _error = store.load_licence()
    if licence_channel_offline(licence):
        return True
    note_offline_contact(licence)
    return False


def _offline_refusal() -> int:
    print_error(
        "Offline mode is on, so ADscan will not contact the licence server. Use --relay-out FILE "
        "(or `adscan license relay export`) and send the request from a machine that can reach ADscan."
    )
    return 1


def add_pull_choice_arguments(parser: Any) -> None:
    """``--pull`` / ``--no-pull`` for the download offered after activation."""
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--pull",
        "--yes",
        dest="pull",
        action="store_const",
        const=True,
        default=None,
        help="Download ADscan PRO right after activation without asking.",
    )
    group.add_argument(
        "--no-pull",
        dest="pull",
        action="store_const",
        const=False,
        help="Activate only; download ADscan PRO later with `adscan update`.",
    )


_KEY_ON_ARGV_WARNING = (
    "The activation key on the command line stays in your shell history and the process list. "
    "--key-file or --key-stdin avoid that."
)


def _read_activation_key(ns: argparse.Namespace) -> str | None:
    positional = str(getattr(ns, "key", "") or "").strip()
    if positional:
        if ns.key_file or ns.key_stdin:
            print_error("Give the activation key once: as an argument, --key-file or --key-stdin.")
            return None
        print_warning(_KEY_ON_ARGV_WARNING)
        return positional
    if ns.key_file:
        try:
            return Path(ns.key_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            print_error(f"The key file cannot be read: {exc.strerror or exc}.")
            return None
    if ns.key_stdin:
        return sys.stdin.readline().strip()
    env = os.getenv(ACTIVATION_KEY_ENV, "").strip()
    if env:
        return env
    from adscan_core.interaction import is_non_interactive

    if is_non_interactive():
        print_error(
            "No activation key. In an unattended run pass it with --key-file, --key-stdin or the "
            f"{ACTIVATION_KEY_ENV} environment variable."
        )
        return None
    from adscan_core.rich_output import prompt_ask

    return (prompt_ask("Activation key (from your onboarding email)", password=True) or "").strip()


def _print_status_lines(status: Any, store: Any) -> None:
    lic = status.licence
    if lic is not None:
        print_info(f"Licence: {lic.label} for {mark_sensitive(lic.customer, 'user')}")
        if lic.partner_tag:
            print_info(f"Partner: {lic.partner_tag}")
        print_info(f"Valid until: {lic.valid_until.isoformat()}")
    installation = store.existing_installation()
    if installation is not None:
        print_info(f"Installation: {installation.installation_id}")


def _print_activation_disclosure(store: Any = None) -> None:
    """Tell a newly activated PRO user what ADscan sends: telemetry, and the licence check-in."""
    from rich.console import Group
    from rich.table import Table
    from rich.text import Text

    from adscan_core.rich_output import print_panel
    from adscan_core.telemetry import _is_telemetry_enabled
    from adscan_core.telemetry_disclosure import (
        ACTIVATION_PANEL_TITLE,
        LICENCE_ACTIVATION_ROWS,
        LICENCE_ACTIVATION_TITLE,
        TELEMETRY_ACTIVATION_ROWS,
        TELEMETRY_ACTIVATION_TITLE,
    )

    def _block(title: str, rows: tuple[tuple[str, str], ...]) -> list[Any]:
        grid = Table.grid(padding=(0, 1))
        grid.add_column(justify="right", style="dim", no_wrap=True, min_width=12)
        grid.add_column(justify="left", ratio=1)
        for label, value in rows:
            grid.add_row(label, value)
        return [Text(title, style="bold"), grid]

    try:
        blocks: list[Any] = []
        if _is_telemetry_enabled():
            blocks += _block(TELEMETRY_ACTIVATION_TITLE, TELEMETRY_ACTIVATION_ROWS)
        needs_server = True
        try:
            licence, _error = store.load_licence()
            needs_server = licence is None or bool(licence.needs_server)
        except Exception:  # noqa: BLE001 - unknown licence: state the channel
            pass
        if needs_server:
            if blocks:
                blocks.append(Text(""))
            blocks += _block(LICENCE_ACTIVATION_TITLE, LICENCE_ACTIVATION_ROWS)
        if blocks:
            print_panel(Group(*blocks), title=ACTIVATION_PANEL_TITLE, border_style="cyan")
    except Exception:  # noqa: BLE001 - a disclosure must never fail an activation
        return


# ── Subcommands ──────────────────────────────────────────────────────────────


def _cmd_activate(ns: argparse.Namespace) -> int:
    key = _read_activation_key(ns)
    if not key:
        return 1
    rc = activate_with_key(key, seat_label=ns.seat_label, relay_out=ns.relay_out)
    if rc != 0 or ns.relay_out:
        return rc
    from adscan_launcher.pro_download import offer_pro_download

    return 0 if offer_pro_download(pull=getattr(ns, "pull", None)) else 1


def activate_with_key(key: str, *, seat_label: str | None = None, relay_out: str | None = None) -> int:
    """Activate this machine with ``key``; return the exit code (shared by ``install --license``)."""
    from adscan_core.pro_license import client

    store = _store()
    if relay_out:
        result = client.activate(store, key, transport=None, seat_label=seat_label)
        if not result.queued:
            print_error(result.message)
            return 1
        client.write_relay_batch(client.export_relay(store), relay_out)
        print_success(
            f"Activation request written to {relay_out}. It contains your activation key, so keep it "
            "private. Send it through your platform, then run `adscan license relay import --in <answers file>`."
        )
        return 0
    if _offline():
        return _offline_refusal()
    result = client.activate(store, key, transport=_transport(), seat_label=seat_label)
    if not result.ok:
        (print_warning if result.queued else print_error)(result.message)
        return 1
    from adscan_core.pro_license.evaluation import check_pro_license
    from adscan_launcher.edition import clear_cache

    clear_cache()
    status = check_pro_license(store)
    print_success(f"This machine is activated. {status.message}")
    _print_status_lines(status, store)
    _print_activation_disclosure(store)
    return 0


def _cmd_status(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client, evaluation
    from adscan_core.pro_license.status_view import render_status_panel, status_document

    store = _store()
    required = evaluation.enforcement_required(store)
    result = None
    if not getattr(ns, "no_check_in", False) and store.has_licence_file():
        result = client.launch_check_in(store)
        if result is not None and result.error is not None:
            from adscan_core import telemetry
            from adscan_core.rich_output import print_exception

            telemetry.capture_exception(result.error)
            print_exception(exception=result.error)
    status = evaluation.check_pro_license(store)
    doc = status_document(store, status, enforced=required, check_in=result)
    if ns.json:
        sys.stdout.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        return 0
    if status.state == evaluation.STATE_MISSING and not required:
        print_info(evaluation.DORMANT_MESSAGE)
        return 0
    from adscan_core.output._state import get_console

    console = get_console()
    console.print(render_status_panel(doc))
    return 0 if status.scans_allowed or not required else 1


def _cmd_deactivate(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client

    store = _store()
    if ns.relay_out:
        result = client.deactivate(store, transport=None)
        if not result.queued:
            print_error(result.message)
            return 1
        batch = client.export_relay(store)
        client.write_relay_batch(batch, ns.relay_out)
        others = len(batch["items"]) - 1
        print_success(
            f"Release request written to {ns.relay_out}"
            + (f", after the {others} queued request{'s' if others != 1 else ''} this machine still owes" if others > 0 else "")
            + ". Send it through your platform."
        )
        return 0
    if _channel_closed(store):
        return _offline_refusal()
    result = client.deactivate(store, transport=_transport())
    (print_success if result.ok else print_error)(result.message)
    if result.ok:
        from adscan_launcher.edition import clear_cache, resolve_edition

        clear_cache()
        if not resolve_edition().is_pro:
            print_info("This machine now runs ADscan LITE. Your workspaces stay available.")
    return 0 if result.ok else 1


def _report_sync(summary: Any) -> int:
    for code, message in summary.notices:
        print_warning(message or code)
    if summary.unreachable:
        print_warning(
            "ADscan could not reach the licence server"
            + (f" ({summary.error})" if summary.error else "")
            + ". Queued requests are kept; try again later or use `adscan license relay export`."
        )
        return 1
    if summary.sent == 0:
        print_info("Nothing to send.")
        return 0
    print_success(f"Sent {summary.sent} request{'s' if summary.sent != 1 else ''}, {summary.applied} answered.")
    if summary.rejected:
        print_warning(f"{len(summary.rejected)} answer(s) could not be accepted.")
    return 0


def _cmd_renew(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client

    store = _store()
    licence, error = store.load_licence()
    if licence is None:
        print_error(str(error) if error else "No PRO licence is active on this machine.")
        return 1
    if _channel_closed(store):
        return _offline_refusal()
    result = client.check_in(store, _transport(), force=True)
    if result.outcome == client.CHECK_IN_REFRESHED:
        from adscan_core.pro_license.evaluation import check_pro_license

        print_success(f"Licence refreshed. {check_pro_license(store).message}")
        return 0
    if result.outcome == client.CHECK_IN_UNREACHABLE:
        print_warning(
            "ADscan could not reach the licence server"
            + (f" ({result.message})" if result.message else "")
            + ". Try again later, or use `adscan license relay export`."
        )
        return 1
    (print_error if result.outcome == client.CHECK_IN_REVOKED else print_warning)(
        result.message or "The licence server's answer could not be accepted."
    )
    return 1


def _cmd_sync(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client

    store = _store()
    if _channel_closed(store):
        return _offline_refusal()
    return _report_sync(client.sync(store, _transport()))


_STEP_LABELS = {
    "proxy": "Proxy",
    "dns": "DNS",
    "tcp": "Connection",
    "tls": "TLS",
    "health": "Server",
    "clock": "Clock",
}


def _check_document(store: Any, report: Any, *, sent: Any, requeued: int, check_in: Any) -> dict[str, Any]:
    """The ``license_check`` document (``adscan license check --json``)."""
    from adscan_core.engagement.output_formats import SCHEMA_VERSION_KEY, output_marker
    from adscan_core.pro_license import evaluation
    from adscan_core.pro_license.connection import licence_notice, notice_block
    from adscan_core.pro_license.route_check import fix_for

    licence_part = None
    notice_part = None
    if store.has_licence_file():
        status = evaluation.check_pro_license(store)
        notice = licence_notice(store, status, check_in=check_in)
        notice_part = notice_block(notice)
        lic = status.licence
        licence_part = {
            "state": status.state,
            "scans_allowed": status.scans_allowed,
            "contract_ends_on": lic.contract_ends_on.isoformat() if lic and lic.contract_ends_on else None,
            "works_offline_until": notice.offline_last_day.isoformat()
            if notice and notice.offline_last_day
            else None,
            "offline_days_left": notice.offline_days_left if notice else None,
            "registered_domains": notice.registered if notice else 0,
            "pending_domains": len(notice.waiting) if notice else 0,
        }
    return {
        SCHEMA_VERSION_KEY: output_marker("license_check"),
        "reachable": report.reachable,
        "cause": report.cause,
        "fix": fix_for(report) or None,
        "route": report.to_dict(),
        "sent": None
        if sent is None
        else {"requests": int(sent.sent), "answered": int(sent.applied), "requeued_after_clock": requeued},
        "licence": licence_part,
        "licence_notice": notice_part,
    }


def _render_check(doc: dict[str, Any], report: Any) -> None:
    from rich import box
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from adscan_core.output._state import get_console
    from adscan_core.pro_license.connection import human_date as _human

    table = Table(box=None, show_header=False, padding=(0, 2, 0, 0), expand=False)
    table.add_column(no_wrap=True)
    table.add_column(style="dim", no_wrap=True)
    table.add_column()
    for step in report.steps:
        mark = Text("–", style="dim") if step.ok is None else (
            Text("✓", style="green") if step.ok else Text("✗", style="bold red")
        )
        table.add_row(mark, _STEP_LABELS.get(step.name, step.name), Text(step.detail))
    parts: list[Any] = [table]
    if doc.get("fix"):
        parts += [Text(""), Text(str(doc["fix"]), style="bold")]
    if report.container_proxy_hint:
        parts += [
            Text(""),
            Text(
                "This machine uses a proxy from HTTPS_PROXY. Scans run in a container that does not "
                "inherit it, so set ADSCAN_LICENSE_PROXY to the same proxy for every launch to check in.",
                style="yellow",
            ),
        ]
    sent = doc.get("sent")
    if sent:
        line = f"Sent {sent['requests']} request{'s' if sent['requests'] != 1 else ''}, {sent['answered']} answered."
        if sent.get("requeued_after_clock"):
            line += (
                f" {sent['requeued_after_clock']} domain registration(s) refused earlier for a wrong clock "
                "were sent again."
            )
        parts += [Text(""), Text(line)]
    lic = doc.get("licence")
    if lic:
        summary = Table(box=None, show_header=False, padding=(0, 2, 0, 0), expand=False)
        summary.add_column(style="dim", no_wrap=True)
        summary.add_column()
        if lic.get("contract_ends_on"):
            from datetime import date

            summary.add_row("Licence valid until", _human(date.fromisoformat(lic["contract_ends_on"])))
        if lic.get("works_offline_until"):
            from datetime import date

            days = lic.get("offline_days_left")
            when = _human(date.fromisoformat(lic["works_offline_until"]))
            summary.add_row("Works offline until", f"{when} ({days} day{'s' if days != 1 else ''} left)")
        summary.add_row(
            "Domains", f"{lic.get('registered_domains', 0)} registered, {lic.get('pending_domains', 0)} waiting"
        )
        parts += [Text(""), summary]
    from adscan_core.pro_license.evaluation import licence_contact_email

    parts += [Text(""), Text(f"Need help? Write to {licence_contact_email()}.", style="dim")]
    reachable = bool(doc.get("reachable"))
    get_console().print(
        Panel(
            Group(*parts),
            title="[bold]Licence server[/bold] · " + ("reachable" if reachable else "not reachable"),
            title_align="left",
            border_style="green" if reachable else "red",
            box=box.ROUNDED,
            padding=(1, 2),
            expand=False,
        )
    )


def _cmd_check(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client
    from adscan_core.pro_license.route_check import diagnose

    store = _store()
    licence, _error = store.load_licence()
    if licence is not None and not licence.needs_server:
        print_info(
            "This is an offline engagement licence. It never contacts the licence server, "
            "so there is nothing to check."
        )
        return 0
    if licence is None and _offline():
        return _offline_refusal()
    if licence is not None and not ns.json:
        _channel_closed(store)  # prints the one offline-mode line when offline mode is on
    report = diagnose(licence_dir=store.directory)
    sent = None
    requeued = 0
    check_in = None
    if licence is not None:
        if report.reachable:
            requeued = client.requeue_clock_refused_registrations(store, licence)
            transport = _transport()
            check_in = client.check_in(store, transport, force=True)
            sent = client.sync(store, transport)
            # The renewal and what it flushed count too.
            sent.sent += 1 + check_in.flushed
            sent.applied += check_in.flushed + (0 if check_in.outcome == client.CHECK_IN_UNREACHABLE else 1)
        else:
            failed = report.failed
            store.record_check_in(client.CHECK_IN_UNREACHABLE, error=failed.detail if failed else "")
            check_in = client.CHECK_IN_UNREACHABLE
    doc = _check_document(store, report, sent=sent, requeued=requeued, check_in=check_in)
    if ns.json:
        sys.stdout.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    else:
        _render_check(doc, report)
        if sent is not None:
            for _code, message in sent.notices:
                print_warning(message)
    return 0 if report.reachable else 1


def _cmd_relay(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client

    store = _store()
    if ns.relay_command == "export":
        batch = client.export_relay(store)
        client.write_relay_batch(batch, ns.out)
        if ns.out != "-":
            count = len(batch["items"])
            print_success(f"{count} request{'s' if count != 1 else ''} written to {ns.out}.")
        return 0
    try:
        batch = client.read_relay_batch(ns.in_file)
    except (OSError, ValueError) as exc:
        print_error(f"The answers file cannot be read: {exc}.")
        return 1
    from adscan_core.pro_license.evaluation import check_pro_license

    had_licence = check_pro_license(store).licence is not None
    summary = client.import_relay(store, batch)
    for code, message in summary.notices:
        print_warning(message or code)
    print_info(f"{summary.applied} answer{'s' if summary.applied != 1 else ''} applied.")
    real_rejections = [r for r in summary.rejected if r[1] != "already_applied"]
    if real_rejections:
        reasons = sorted({reason for _rid, reason in real_rejections})
        print_warning(f"{len(real_rejections)} answer(s) rejected ({', '.join(reasons)}).")
        return 1
    if not had_licence and summary.applied and check_pro_license(store).licence is not None:
        _print_activation_disclosure(store)
    return 0


def _register_csv(export: dict, rows: str) -> str:
    """The register export as CSV, one row per code, engagement or assessment."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    tag = export.get("partner_tag") or ""
    if rows == "engagements":
        writer.writerow(
            ["domain_code", "opened_at", "band", "retest_until", "opened_by_run_id", "retests", "rechecks", "partner_tag"]
        )
        for e in export["engagements"]:
            writer.writerow(
                [e["domain_code"], e["opened_at"], e["band"] or "", e["retest_until"], e["opened_by_run_id"],
                 len(e["retest_run_ids"]), len(e["recheck_run_ids"]), tag]
            )
    elif rows == "assessments":
        writer.writerow(["domain_code", "run_kind", "assessed_at", "run_id", "parent_run_id", "band", "partner_tag"])
        for a in export["assessments"]:
            writer.writerow(
                [a["domain_code"], a["run_kind"], a["assessed_at"], a["run_id"], a["parent_run_id"] or "",
                 a["band"] or "", tag]
            )
    else:
        writer.writerow(["domain_code", "status", "band", "first_seen", "registered_at", "receipt_id", "receipt_verified"])
        for e in export["entries"]:
            writer.writerow(
                [e["domain_code"], e["status"], e["band"], e["first_seen"], e["registered_at"], e["receipt_id"], e["receipt_verified"]]
            )
    return buffer.getvalue()


def _cmd_register(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client

    export = client.register_export(_store())
    if ns.format == "csv":
        text = _register_csv(export, getattr(ns, "rows", "codes") or "codes")
    else:
        text = json.dumps(export, indent=2, sort_keys=True) + "\n"
    if ns.out == "-":
        sys.stdout.write(text)
    else:
        Path(ns.out).write_text(text, encoding="utf-8")
        print_success(f"Register written to {ns.out} ({len(export['entries'])} domain codes).")
    return 0


def _cmd_install(ns: argparse.Namespace) -> int:
    from adscan_core.enterprise_license import LicenseError
    from adscan_core.pro_license import client

    try:
        raw = Path(ns.file).read_bytes()
        licence = client.install_offline_licence(_store(), raw)
    except OSError as exc:
        print_error(f"The licence file cannot be read: {exc.strerror or exc}.")
        return 1
    except LicenseError as exc:
        print_error(f"The licence file cannot be accepted: {exc}")
        return 1
    print_success(f"{licence.label} licence installed, valid until {licence.valid_until.isoformat()}.")
    return 0


_HANDLERS = {
    "activate": _cmd_activate,
    "status": _cmd_status,
    "show": _cmd_status,
    "deactivate": _cmd_deactivate,
    "renew": _cmd_renew,
    "sync": _cmd_sync,
    "check": _cmd_check,
    "relay": _cmd_relay,
    "register": _cmd_register,
    "install": _cmd_install,
}


def run_license_command(ns: argparse.Namespace) -> int:
    """Dispatch ``adscan license <subcommand>``; return the exit code."""
    handler = _HANDLERS.get(str(getattr(ns, "license_command", "") or ""))
    if handler is None:
        print_error(f"Unknown license subcommand. Use one of: {', '.join(sorted(_HANDLERS))}.")
        return 2
    try:
        return handler(ns)
    except Exception as exc:  # noqa: BLE001 - a launcher command reports, never tracebacks at the user
        from adscan_core import telemetry
        from adscan_core.rich_output import print_exception

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("The licence command failed. Run it again with --debug for details.")
        return 1


__all__ = [
    "ACTIVATION_KEY_ENV",
    "activate_with_key",
    "add_license_subparser",
    "add_pull_choice_arguments",
    "run_license_command",
]
