"""``adscan engagement status|history|export``: read the engagement ledger.

The ledger (``<workspace>/engagement/engagement.sqlite``) is written at the end of
every recorded PRO / Enterprise run; this command only reads it. It never
creates a ledger: a workspace with no recorded run says so and exits 2.

* ``status``: one row per finding and attack step with its lifecycle status,
  whether the latest run re-checked it, and when it was last verified;
* ``history``: the status changes of one finding (by catalog key or id) or
  item, run by run;
* ``export``: regenerate ``engagement/export/ledger.json`` (``adscan.ledger/1``).

``--json`` prints machine-readable output instead of the table. PRO only
(``adscan_core.cli_catalog.PRO_ONLY_COMMANDS``).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any

from adscan_core import telemetry
from adscan_core.engagement.identity import finding_id
from adscan_core.engagement.store import (
    EXPORT_DIRNAME,
    STORE_DIRNAME,
    EngagementStoreError,
    open_store,
    store_path,
)
from adscan_core.paths import get_workspaces_dir
from rich.table import Table

from adscan_core.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_success,
    print_table,
)

ACTIONS = ("status", "history", "export")
KINDS = ("findings", "steps", "all")


def add_engagement_subparser(subparsers: Any) -> argparse.ArgumentParser:
    """Register the container ``adscan engagement`` subparser (ENGAGEMENT_PASSTHROUGH)."""
    parser = subparsers.add_parser(
        "engagement",
        help="Engagement history: lifecycle of every finding and attack step across runs.",
        description=(
            "Read the engagement ledger a workspace keeps across recorded runs: what is "
            "open, what was fixed, what the latest run could not re-check, and when each "
            "item was last verified."
        ),
    )
    parser.add_argument("action", choices=ACTIONS, help="status, history or export.")
    parser.add_argument("--workspace", "-w", required=True, metavar="NAME", help="Workspace name.")
    parser.add_argument("--finding", metavar="KEY|ID", help="history: a finding key or finding id.")
    parser.add_argument("--item", metavar="ID", help="history: a ledger item id.")
    parser.add_argument("--domain", metavar="DOMAIN", help="Only this domain.")
    parser.add_argument("--kind", choices=KINDS, default="findings",
                        help="status: findings (default), steps or all.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a table.")
    return parser


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _domain(value: Any) -> str | None:
    text = str(value or "").strip().rstrip(".").lower()
    return text or None


def _status_rows(store: Any, args: argparse.Namespace) -> list[dict[str, Any]]:
    kinds = {"findings": ("finding",), "steps": ("step",), "all": None}[args.kind]
    rows = store.items(domain_id=_domain(args.domain))
    return [r for r in rows if kinds is None or r["kind"] in kinds]


def _table(title: str, columns: list[str], rows: list[list[str]]) -> Table:
    table = Table(title=title, show_lines=False)
    for column in columns:
        table.add_column(column)
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    return table


def _emit_json(doc: Any) -> None:
    # Machine output on stdout for scripts (as ``doctor --json`` does).
    sys.stdout.write(json.dumps(doc, indent=2, sort_keys=True, default=str) + "\n")
    sys.stdout.flush()


def _print_status(rows: list[dict[str, Any]]) -> None:
    if not rows:
        print_info("No items in the engagement ledger for this selection.")
        return
    table_rows = []
    for row in rows:
        status = row["disposition"] or row["status"]
        checked = "not re-checked" if row["evaluation_state"] == "not_reevaluated" else "re-checked"
        table_rows.append([
            mark_sensitive(row["domain_id"], "domain"),
            row["label"] or row["key"],
            status,
            checked,
            str(row["last_verified_at"] or "")[:10],
            row["item_id"][:12],
        ])
    print_table(_table("Engagement status", ["Domain", "Item", "Status", "Latest run",
                                             "Last verified", "Id"], table_rows))


def _history(store: Any, args: argparse.Namespace) -> dict[str, Any]:
    if args.item:
        ids = [args.item]
    elif args.finding:
        token = str(args.finding).strip()
        candidates = [r for r in store.items(kind="finding") if r["item_id"] == token or r["key"] == token]
        domain = _domain(args.domain)
        ids = [
            r["item_id"]
            for r in candidates
            if domain is None or r["domain_id"] == domain
        ] or ([finding_id(token, domain)] if domain else [])
    else:
        raise ValueError("history needs --finding or --item")
    out: dict[str, Any] = {}
    for item_id in ids:
        row = store.item(item_id)
        if row is None:
            continue
        out[item_id] = {**row, "events": store.history(item_id)}
    return out


def _print_history(items: dict[str, Any]) -> None:
    if not items:
        print_info("No history for that item in this engagement.")
        return
    for item_id, item in items.items():
        rows = [
            [str(e["at"])[:19], e["run_id"], e["transition"], e["old_status"] or "", e["new_status"]]
            for e in item["events"]
        ]
        title = f"{item['label'] or item['key']} ({mark_sensitive(item['domain_id'], 'domain')}, {item_id[:12]})"
        print_table(_table(title, ["When", "Run", "Change", "From", "To"], rows))
        if item["evaluation_state"] == "not_reevaluated":
            print_info("Not re-checked in the latest run: the check that observes it did not run on this scope.")


def handle_engagement_command(args: argparse.Namespace) -> int:
    """``adscan engagement ...`` (container). 0 on success, 2 on a user error."""
    workspace = get_workspaces_dir() / str(args.workspace)
    if not workspace.is_dir():
        print_error(f"No workspace named '{mark_sensitive(str(args.workspace), 'workspace')}'.")
        return 2
    if not store_path(workspace).is_file():
        print_error(
            "This workspace has no engagement history yet: it is recorded at the end of "
            "every `adscan ci` run."
        )
        return 2
    try:
        store = open_store(store_path(workspace))
    except EngagementStoreError as exc:
        print_error(str(exc))
        return 2
    try:
        if args.action == "export":
            path = store.export(workspace / STORE_DIRNAME / EXPORT_DIRNAME, generated_at=_now())
            print_success(f"Engagement ledger exported to {mark_sensitive(str(path), 'path')}")
            return 0
        if args.action == "status":
            if args.json:
                doc = store.export_document(generated_at=_now())
                domain = _domain(args.domain)
                if domain:
                    doc["items"] = [i for i in doc["items"] if i["domain_id"] == domain]
                _emit_json(doc)
            else:
                _print_status(_status_rows(store, args))
            return 0
        try:
            items = _history(store, args)
        except ValueError as exc:
            print_error(str(exc))
            return 2
        if args.json:
            _emit_json({"schema": "adscan.engagement_history/1", "items": items})
        else:
            _print_history(items)
        return 0
    except Exception as exc:  # noqa: BLE001 - one command, one exit code
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("The engagement command failed.")
        return 1
    finally:
        store.close()


__all__ = ("ACTIONS", "add_engagement_subparser", "handle_engagement_command")
