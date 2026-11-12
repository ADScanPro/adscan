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
            "email. After that the licence is checked on this machine without connecting on every run. "
            + _RELAY_HELP
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    lsub = lic.add_subparsers(dest="license_command", metavar="subcommand", required=True)

    act = lsub.add_parser("activate", help="Activate this machine (once).")
    src = act.add_mutually_exclusive_group()
    src.add_argument("--key-file", help="Read the activation key from this file.")
    src.add_argument("--key-stdin", action="store_true", help="Read the activation key from standard input.")
    act.add_argument("--seat-label", help="A name for this seat, shown to your account (no hostname is sent).")
    act.add_argument(
        "--relay-out",
        metavar="FILE",
        help="Do not connect. Write the activation request to FILE for your platform to forward.",
    )

    st = lsub.add_parser("status", help="Show the licence, its expiry and the domains waiting to be registered.")
    st.add_argument("--json", action="store_true", help="Machine-readable output.")

    de = lsub.add_parser("deactivate", help="Release this machine's seat and remove its licence.")
    de.add_argument("--relay-out", metavar="FILE", help="Write the release request to FILE instead of connecting.")

    lsub.add_parser("renew", help="Ask for a fresh licence document now.")
    lsub.add_parser("sync", help="Send every queued request (new domains, band updates, renewal) now.")

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
    from adscan_core.offline import offline_mode_enabled

    return offline_mode_enabled()


def _offline_refusal() -> int:
    print_error(
        "Offline mode is on, so ADscan will not contact the licence server. Use --relay-out FILE "
        "(or `adscan license relay export`) and send the request from a machine that can reach ADscan."
    )
    return 1


def _read_activation_key(ns: argparse.Namespace) -> str | None:
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


# ── Subcommands ──────────────────────────────────────────────────────────────


def _cmd_activate(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client

    key = _read_activation_key(ns)
    if not key:
        return 1
    store = _store()
    if ns.relay_out:
        result = client.activate(store, key, transport=None, seat_label=ns.seat_label)
        if not result.queued:
            print_error(result.message)
            return 1
        client.write_relay_batch(client.export_relay(store), ns.relay_out)
        print_success(
            f"Activation request written to {ns.relay_out}. It contains your activation key, so keep it "
            "private. Send it through your platform, then run `adscan license relay import --in <answers file>`."
        )
        return 0
    if _offline():
        return _offline_refusal()
    result = client.activate(store, key, transport=_transport(), seat_label=ns.seat_label)
    if not result.ok:
        (print_warning if result.queued else print_error)(result.message)
        return 1
    from adscan_core.pro_license.evaluation import check_pro_license

    status = check_pro_license(store)
    print_success(f"This machine is activated. {status.message}")
    _print_status_lines(status, store)
    if store.registry_credential():
        print_info("A read-only image registry credential was saved with the licence.")
    return 0


def _cmd_status(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import evaluation
    from adscan_core.pro_license.state import STATUS_PENDING, STATUS_REFUSED, STATUS_REGISTERED

    store = _store()
    status = evaluation.check_pro_license(store)
    required = evaluation.enforcement_required(store)
    entries = store.register_entries().values()
    counts = {
        "registered": sum(1 for e in entries if e.get("status") == STATUS_REGISTERED),
        "pending": sum(1 for e in entries if e.get("status") == STATUS_PENDING),
        "refused": sum(1 for e in entries if e.get("status") == STATUS_REFUSED),
    }
    if ns.json:
        installation = store.existing_installation()
        data = status.to_dict()
        data.update(
            {
                "enforcement": "required" if required else "dormant",
                "installation_id": installation.installation_id if installation else None,
                "domains": counts,
                "queued_requests": len(store.pending()),
                "last_contact": store.last_contact(),
            }
        )
        sys.stdout.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
        return 0
    if status.state == evaluation.STATE_MISSING and not required:
        print_info(
            "No ADscan PRO licence is installed on this machine. This build does not require one yet; "
            "activate with `adscan license activate` when you receive an activation key."
        )
        return 0
    (print_success if status.scans_allowed and not status.warning else print_warning)(status.message)
    _print_status_lines(status, store)
    print_info(
        f"Domains: {counts['registered']} registered, {counts['pending']} waiting to be registered"
        + (f", {counts['refused']} refused" if counts["refused"] else "")
        + "."
    )
    queued = len(store.pending())
    if queued:
        print_info(
            f"{queued} request{'s' if queued != 1 else ''} queued. Send with `adscan license sync`, "
            "or through your platform with `adscan license relay export`."
        )
    return 0 if status.scans_allowed or not required else 1


def _cmd_deactivate(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client

    store = _store()
    if ns.relay_out:
        result = client.deactivate(store, transport=None)
        if not result.queued:
            print_error(result.message)
            return 1
        client.write_relay_batch(client.export_relay(store), ns.relay_out)
        print_success(f"Release request written to {ns.relay_out}. Send it through your platform.")
        return 0
    if _offline():
        return _offline_refusal()
    result = client.deactivate(store, transport=_transport())
    (print_success if result.ok else print_error)(result.message)
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
    from adscan_core.pro_license import client, documents

    store = _store()
    licence, error = store.load_licence()
    if licence is None:
        print_error(str(error) if error else "No PRO licence is active on this machine.")
        return 1
    if _offline():
        return _offline_refusal()
    if store.pending_of_kind(documents.KIND_RENEWAL, license_id=licence.license_id) is None:
        store.add_pending(
            documents.build_request(
                store.installation(),
                documents.KIND_RENEWAL,
                engine_version=client.engine_version(),
                license_id=licence.license_id,
            )
        )
    return _report_sync(client.sync(store, _transport()))


def _cmd_sync(ns: argparse.Namespace) -> int:
    from adscan_core.pro_license import client

    if _offline():
        return _offline_refusal()
    return _report_sync(client.sync(_store(), _transport()))


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
    summary = client.import_relay(store, batch)
    for code, message in summary.notices:
        print_warning(message or code)
    print_info(f"{summary.applied} answer{'s' if summary.applied != 1 else ''} applied.")
    real_rejections = [r for r in summary.rejected if r[1] != "already_applied"]
    if real_rejections:
        reasons = sorted({reason for _rid, reason in real_rejections})
        print_warning(f"{len(real_rejections)} answer(s) rejected ({', '.join(reasons)}).")
        return 1
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
    "deactivate": _cmd_deactivate,
    "renew": _cmd_renew,
    "sync": _cmd_sync,
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


__all__ = ["ACTIVATION_KEY_ENV", "add_license_subparser", "run_license_command"]
