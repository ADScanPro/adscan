"""``adscan recheck``: re-verify findings, attack steps and attack paths.

A target runner over the engagement ledger (spec section 10). ``execute`` stays
the technique runner (decision D13); at ``exercise`` / ``walk`` depth ``recheck``
hands the route to the same attack-path loop ``attack_paths`` uses.

* ``--all``: every open finding and attack step;
* ``--finding KEY [--object ID ...] [--filter EXPR]``: one finding and the steps
  that back it, optionally narrowed to named objects;
* ``--step ID``: one attack step (``--depth exercise`` re-performs it);
* ``--path ID [--walk]``: one attack path (``--walk`` executes it end to end).
  ``ID`` is the path id the report prints next to each path (any unambiguous
  prefix of 8+ characters of the ``path_id`` in ``attack_paths_snapshot.json``),
  or the ``P-XXXXXXXX`` label an older Word report printed.

``-u/--username`` with ``-p/--password`` gives the reads an account for this run
only (the audit account is often disabled after an engagement). It goes through
the same credential SSOT and lockout guard as the workspace's account and is
never written into the workspace.

``--json`` writes the result document (``adscan.recheck_result/1``) to stdout
and nothing else; every human line goes to stderr.

``--depth observe`` (the default) only reads. Without a target the run re-checks
every open item read-only; ``exercise`` and ``walk`` are never inferred. PRO only
(``adscan_core.cli_catalog.PRO_ONLY_COMMANDS``, decision D12b).
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from rich.markup import escape
from rich.table import Table

if TYPE_CHECKING:
    from adscan_internal.services.recheck.runner import ReadCredential

from adscan_core import telemetry
from adscan_core.engagement.model import Transition
from adscan_core.engagement.recheck import (
    DEPTH_OBSERVE,
    DEPTH_WALK,
    DEPTHS,
    LEVEL_ALL,
    LEVEL_FINDING,
    LEVEL_PATH,
    LEVEL_STEP,
    REASON_LABELS,
    REASON_NO_READ_ONLY_CHECK,
    VERDICT_NOT_RECHECKED,
    RecheckError,
    RecheckTarget,
    parse_filter,
    validate_target,
)
from adscan_core.engagement.store import EngagementStoreError, store_path
from adscan_core.output.machine_output import machine_readable_stdout, write_machine_document
from adscan_core.paths import get_workspaces_dir
from adscan_core.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_success,
    print_table,
    print_warning,
)

#: How the ledger change of each item reads in the summary table.
_LEDGER_LABELS = {
    Transition.NEW.value: "new",
    Transition.STILL_PRESENT.value: "still open",
    Transition.REOPENED.value: "reopened",
    Transition.REMEDIATED.value: "closed",
    Transition.NOT_REEVALUATED.value: "unchanged",
    Transition.TERMINAL_UNCHANGED.value: "client decision kept",
}


def add_recheck_subparser(subparsers: Any) -> argparse.ArgumentParser:
    """Register the container ``adscan recheck`` subparser (RECHECK_PASSTHROUGH)."""
    parser = subparsers.add_parser(
        "recheck",
        help="Re-verify findings, attack steps and attack paths from the engagement ledger.",
        description=(
            "Re-verify what a previous scan found, without a full scan. observe re-reads "
            "the condition (read-only, the default); exercise re-performs one attack step; "
            "--walk executes one attack path end to end. Results update the engagement "
            "ledger. With no target, every open item is re-checked read-only."
        ),
    )
    parser.add_argument("--workspace", "-w", required=True, metavar="NAME", help="Workspace name.")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--all", action="store_true", dest="all_items",
                        help="Every open finding and attack step (the default without a target).")
    target.add_argument("--finding", metavar="KEY|ID", help="A finding key (for example kerberoast) or id.")
    target.add_argument("--step", metavar="ID", help="An attack step id (8+ characters).")
    target.add_argument(
        "--path",
        metavar="ID",
        help="An attack path id: the id the report prints next to the path (8+ characters).",
    )
    parser.add_argument("--object", action="append", default=[], metavar="ID", dest="objects",
                        help="With --finding: only this affected object (a SID). Repeatable.")
    parser.add_argument("--filter", metavar="EXPR", dest="filter_expr",
                        help="With --all or --finding: domain=<domain>,status=open|remediated|not_reevaluated|all.")
    parser.add_argument("--depth", choices=DEPTHS, default=None,
                        help="observe (read-only, default), exercise (re-perform a step) or walk (a path).")
    parser.add_argument("--walk", action="store_true", help="With --path: same as --depth walk.")
    parser.add_argument(
        "-u", "--username", "--user", dest="username", metavar="USER",
        help="Read with this account instead of the workspace's (user, user@domain or DOMAIN\\user). "
        "This run only; never stored.",
    )
    parser.add_argument(
        "-p", "--password", dest="password", metavar="SECRET",
        help="Password or NT hash of --username.",
    )
    parser.add_argument("--json", action="store_true",
                        help="Print only the result document, as JSON, on stdout.")
    return parser


def read_credential_from_args(args: argparse.Namespace) -> Optional["ReadCredential"]:
    """The ``-u/-p`` override, or ``None``; raises :class:`RecheckError` when half-given."""
    from adscan_internal.services.recheck.runner import ReadCredential  # noqa: PLC0415

    user = str(getattr(args, "username", None) or "").strip()
    secret = getattr(args, "password", None)
    if not user and secret is None:
        return None
    if not user or not secret:
        raise RecheckError("--username and --password go together: pass both, or neither.")
    credential = ReadCredential(username=user, secret=str(secret))
    if not credential.account:
        raise RecheckError("--username needs an account name.")
    return credential


def request_from_args(args: argparse.Namespace) -> tuple[RecheckTarget, str, bool]:
    """``(target, depth, defaulted)`` from parsed flags; raises :class:`RecheckError`."""
    depth: Optional[str] = args.depth
    if getattr(args, "walk", False):
        if not args.path:
            raise RecheckError("--walk applies to an attack path; use it with --path.")
        if depth not in (None, DEPTH_WALK):
            raise RecheckError("--walk and --depth disagree; use one of them.")
        depth = DEPTH_WALK
    filters = parse_filter(args.filter_expr) if args.filter_expr else ()
    defaulted = False
    if args.finding:
        target = RecheckTarget(level=LEVEL_FINDING, finding=args.finding, objects=tuple(args.objects),
                               filters=filters)
    elif args.step:
        target = RecheckTarget(level=LEVEL_STEP, step=args.step)
    elif args.path:
        target = RecheckTarget(level=LEVEL_PATH, path=args.path)
    else:
        if depth not in (None, DEPTH_OBSERVE):
            raise RecheckError(
                f"--depth {depth} needs an explicit target (--step for exercise, --path for walk); "
                "it is never applied to every item."
            )
        defaulted = not getattr(args, "all_items", False)
        target = RecheckTarget(level=LEVEL_ALL, filters=filters)
    if args.objects and target.level != LEVEL_FINDING:
        raise RecheckError("--object narrows a finding; use it with --finding.")
    if args.filter_expr and target.level not in (LEVEL_ALL, LEVEL_FINDING):
        raise RecheckError("--filter applies to --all or --finding.")
    depth = depth or DEPTH_OBSERVE
    validate_target(target, depth)
    return target, depth, defaulted


def _print_report(report: Any, *, defaulted: bool) -> None:
    verdicts = report.decisions.verdicts
    transitions = {r.item_id: r.transition.value for r in report.decisions.results}
    shown: list[list[Any]] = []
    # Declared reason -> items that have no read-only check for that reason.
    no_check: dict[str, int] = {}
    for item in report.targets:
        verdict = verdicts.get(item.item_id)
        if verdict is None:
            continue
        if verdict.code == VERDICT_NOT_RECHECKED and verdict.reason == REASON_NO_READ_ONLY_CHECK:
            no_check[verdict.detail] = no_check.get(verdict.detail, 0) + 1
            continue
        shown.append([
            mark_sensitive(item.domain_id, "domain"),
            mark_sensitive(item.label or item.key, "user"),
            verdict.text,
            _LEDGER_LABELS.get(transitions.get(item.item_id, ""), "unchanged"),
            item.item_id[:12],
        ])
    if defaulted:
        print_info("No target given: every open finding and attack step was re-checked read-only.")
    if shown:
        table = Table(title="Re-check results", show_lines=False)
        for column in ("Domain", "Item", "Result", "Ledger", "Id"):
            table.add_column(column)
        for row in shown:
            table.add_row(*[str(cell) for cell in row])
        print_table(table)
    if no_check:
        print_info(
            f"{sum(no_check.values())} item(s) have no read-only check in this release and were not "
            "re-checked; they keep their status until the next scan re-evaluates them."
        )
        table = Table(title="Not re-checked, and why", show_lines=False)
        table.add_column("Items", justify="right")
        table.add_column("Why")
        for reason, count in sorted(no_check.items(), key=lambda kv: (-kv[1], kv[0])):
            table.add_row(str(count), escape(reason or REASON_LABELS[REASON_NO_READ_ONLY_CHECK]))
        print_table(table)
    closed = report.count(Transition.REMEDIATED)
    still = report.count(Transition.STILL_PRESENT) + report.count(Transition.REOPENED) + report.count(
        Transition.NEW
    )
    unchanged = report.count(Transition.NOT_REEVALUATED)
    print_success(
        f"Re-check recorded: {closed} closed (observed), {still} still present, "
        f"{unchanged} not re-checked. Evidence: {mark_sensitive(report.result_path, 'path')}"
    )


def run_recheck_command(args: argparse.Namespace, deps: Any) -> int:
    """``adscan recheck`` (container). 0 recorded, 2 user error, 1 failure.

    ``deps`` is the shared bootstrap of ``execute``
    (:class:`adscan_internal.cli.execute.ExecuteDeps`): shell factory, licence
    mode, preflight hooks. With ``--json`` stdout carries the result document
    alone; every other line, an error included, goes to stderr.
    """
    if getattr(args, "json", False):
        with machine_readable_stdout():
            return _run_recheck_command(args, deps)
    return _run_recheck_command(args, deps)


def _run_recheck_command(args: argparse.Namespace, deps: Any) -> int:
    from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

    try:
        target, depth, defaulted = request_from_args(args)
        credential = read_credential_from_args(args)
    except RecheckError as exc:
        print_error(str(exc))
        return 2
    workspace = get_workspaces_dir() / str(args.workspace)
    if not workspace.is_dir():
        print_error(f"No workspace named '{mark_sensitive(str(args.workspace), 'workspace')}'.")
        return 2
    if not store_path(workspace).is_file():
        print_error(
            "This workspace has no engagement history yet, so there is nothing to re-check: "
            "it is recorded at the end of every `adscan ci` run."
        )
        return 2

    from adscan_internal.cli.enterprise_license_gate import (  # noqa: PLC0415
        LICENSE_BLOCKED_EXIT_CODE,
        ensure_license_allows_new_scan,
    )

    if not ensure_license_allows_new_scan("recheck"):
        return LICENSE_BLOCKED_EXIT_CODE

    non_interactive = is_non_interactive()
    if non_interactive:
        os.environ.setdefault("ADSCAN_SESSION_ENV", "ci")
        os.environ["ADSCAN_NONINTERACTIVE"] = "1"
        deps.enable_auto_mode()

    from adscan_core.engagement.run_identity import current_run_id  # noqa: PLC0415
    from adscan_internal.cli.ci_events import (  # noqa: PLC0415
        emit_event,
        emit_run_completed,
        emit_run_started,
    )

    if depth != DEPTH_OBSERVE:
        # Exercise and walk run attack techniques: the same tool and DNS
        # preflight as `execute`. A read-only observe needs only LDAP.
        from adscan_internal.cli.session_preflight import (  # noqa: PLC0415
            SessionPreflightConfig,
            SessionPreflightDeps,
            run_session_preflight,
        )

        run_session_preflight(
            config=SessionPreflightConfig(
                command_name="recheck",
                docs_placement="execute_preflight_failed",
                allow_unsafe_override=False,
            ),
            deps=SessionPreflightDeps(
                build_preflight_args=deps.build_preflight_args,
                handle_check=deps.handle_check,
                get_last_check_extra=deps.get_last_check_extra,
                track_docs_link_shown=deps.track_docs_link_shown,
                confirm_ask=lambda _prompt, _default: False,
                exit=deps.exit,
            ),
        )

    run_id = current_run_id()
    emit_run_started(kind="recheck")
    exit_code = 1
    try:
        shell = _prepare_shell(deps, workspace, non_interactive=non_interactive)
        exit_code = _run(shell, workspace, args, target, depth, defaulted, run_id, emit_event,
                         credential=credential)
        return exit_code
    except Exception as exc:  # noqa: BLE001 - one command, one exit code
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("The re-check failed; nothing was recorded for the items it had not finished.")
        return 1
    finally:
        emit_run_completed(
            kind="recheck",
            status="completed" if exit_code == 0 else "failed",
            exit_code=exit_code,
        )


def _prepare_shell(deps: Any, workspace: Path, *, non_interactive: bool) -> Any:
    from adscan_internal.workspaces.session import activate_workspace  # noqa: PLC0415

    license_mode = deps.resolve_license_mode(False)
    shell = deps.create_shell(deps.console, license_mode)
    shell.session_command_type = "recheck"
    if non_interactive:
        from adscan_internal.services.scan_controls import stamp_unattended_entry  # noqa: PLC0415

        stamp_unattended_entry(shell, "recheck")
        shell.auto = True
    # The scan's artifacts are its record: freeze them before anything loads, so no
    # best-effort writer of the workspace loader or the engine rewrites them.
    from adscan_core.workspace_freeze import freeze_workspace  # noqa: PLC0415

    freeze_workspace(workspace)
    shell.ensure_workspaces_dir()
    activate_workspace(shell, workspaces_dir=shell.workspaces_dir, workspace_name=workspace.name)
    shell.load_workspace_data(str(workspace))
    return shell


def _run(shell: Any, workspace: Path, args: argparse.Namespace, target: RecheckTarget, depth: str,
         defaulted: bool, run_id: str, emit: Any, *, credential: Any = None) -> int:
    from adscan_internal.services.engagement.run_summary import run_stamp  # noqa: PLC0415
    from adscan_internal.services.recheck import walk as walk_mod  # noqa: PLC0415
    from adscan_internal.services.recheck.runner import (  # noqa: PLC0415
        RecheckRequest,
        execute_recheck,
        shell_connector,
    )

    request = RecheckRequest(
        workspace=workspace.name,
        target=target,
        depth=depth,
        override_username=credential.username if credential is not None else "",
    )
    if credential is not None:
        print_info(
            f"The reads use {mark_sensitive(credential.username, 'user')}, given for this run "
            "only; the workspace's own account is not used and nothing is stored."
        )
    observations: list[dict[str, Any]] = []
    try:
        report = execute_recheck(
            workspace,
            request,
            run_id=run_id,
            connect=shell_connector(shell, observations, credential=credential),
            control_observations=observations,
            execute=lambda domain, summary: walk_mod.execute_summary(shell, domain, summary),
            domains=sorted(getattr(shell, "domains_data", {}) or {}),
            stamp=lambda: run_stamp(workspace, clock_released=False),
            emit=emit,
        )
    except RecheckError as exc:
        print_warning(str(exc))
        return 2
    except EngagementStoreError as exc:
        print_error(str(exc))
        return 2
    # The PRO licence usage line: a recheck of the parent scan's domain codes,
    # never billable and never sent to the licence server (dormant without a licence).
    from adscan_internal.cli.pro_license_gate import record_pro_recheck_usage  # noqa: PLC0415

    record_pro_recheck_usage(shell, run_id=run_id, parent_run_id=report.parent_run_id)
    if args.json:
        doc = json.loads((workspace / report.result_path).read_text(encoding="utf-8"))
        write_machine_document(doc)
    else:
        _print_report(report, defaulted=defaulted)
    return 0


__all__ = (
    "add_recheck_subparser",
    "read_credential_from_args",
    "request_from_args",
    "run_recheck_command",
)
