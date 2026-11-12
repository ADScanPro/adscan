"""The ``cleanup_credential set | show | clear`` shell command.

Manages the client-provided cleanup-only account saved in the workspace: the
account ADscan tries first when it undoes its own changes, and never uses for
the assessment. ``show`` never prints the secret; ``set`` always asks for it at a
masked prompt (never as an argument, which would land in the shell history).

Every store access goes through :mod:`cleanup_credential_loader`; this module
never imports the store.
"""

from __future__ import annotations

from typing import Any, Optional

from rich.table import Table

from adscan_core.rich_output import print_error, print_info, print_success, print_table
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cleanup_credential_loader import (
    ANY_DOMAIN,
    CLEANUP_COMMAND,
    ask_for_cleanup_account,
    describe_cleanup_accounts,
    remove_cleanup_accounts,
    save_cleanup_account,
)

__all__ = ["SUBCOMMANDS", "USAGE", "handle_cleanup_credential_command", "known_domains"]

SUBCOMMANDS: tuple[str, ...] = ("set", "show", "check", "clear")

USAGE = (
    f"Usage: {CLEANUP_COMMAND} set [<domain>] | show | check | clear [<domain>|all]\n\n"
    "  set     Save the cleanup-only account your client provided for a domain\n"
    "          (default: the current domain). The secret is asked for at a\n"
    "          masked prompt and saved in this workspace.\n"
    "  show    List the cleanup accounts available, never the secret.\n"
    "  check   Check, without changing anything, what the account can undo in\n"
    "          each in-scope forest, domain and certification authority, and\n"
    "          which techniques that lets your scan policy run.\n"
    "  clear   Remove the saved account for a domain, or every one with 'all'.\n\n"
    "ADscan tries this account first when it undoes its own changes and never uses\n"
    "it for the assessment."
)


def known_domains(shell: Any) -> list[str]:
    """Domains of the workspace, for completion and the default ``set`` target."""
    found: list[str] = []
    for value in [getattr(shell, "domain", None), *(getattr(shell, "domains", None) or [])]:
        text = str(value or "").strip()
        if text and text.lower() not in {d.lower() for d in found}:
            found.append(text)
    return found


def _default_domain(shell: Any) -> str:
    for value in (getattr(shell, "current_domain", None), getattr(shell, "domain", None)):
        text = str(value or "").strip()
        if text:
            return text
    domains = known_domains(shell)
    return domains[0] if len(domains) == 1 else ""


def handle_cleanup_credential_command(shell: Any, args: str) -> None:
    """Parse and dispatch ``cleanup_credential <action> [<domain>]``."""
    parts = (args or "").split()
    action = parts[0].lower() if parts else "show"
    target: Optional[str] = parts[1] if len(parts) > 1 else None
    if action == "show":
        _show()
    elif action == "set":
        _set(shell, target)
    elif action == "check":
        _check(shell)
    elif action == "clear":
        _clear(shell, target)
    else:
        print_error(f"Unknown {CLEANUP_COMMAND} subcommand: {action!r}")
        print_info(USAGE)


def _show() -> None:
    rows = describe_cleanup_accounts()
    if not rows:
        print_info(
            "No cleanup account is configured. Save the one your client provided "
            f"with '{CLEANUP_COMMAND} set'."
        )
        return
    table = Table(title="Cleanup accounts")
    for column in ("Domain", "Account", "Origin"):
        table.add_column(column)
    for row in rows:
        table.add_row(
            mark_sensitive(row.domain, "domain"),
            mark_sensitive(row.principal, "user"),
            row.origin,
        )
    print_table(table)
    print_info("Used only to undo ADscan's changes, never for the assessment.")


def _check(shell: Any) -> None:
    """Re-check, read-only, what the cleanup account can undo, and print it."""
    from adscan_internal.services.cleanup_capability import (  # noqa: PLC0415
        check_and_print,
    )

    if not describe_cleanup_accounts():
        print_info(
            "No cleanup account is configured, so ADscan skips every step whose "
            f"change only such an account can undo. Save one with '{CLEANUP_COMMAND} set'."
        )
    check_and_print(shell, refresh=True)
    saver = getattr(shell, "save_workspace_data", None)
    if callable(saver) and getattr(shell, "current_workspace_dir", None):
        saver()


def _set(shell: Any, target: Optional[str]) -> None:
    domain = target if target is not None else _default_domain(shell)
    if domain == ANY_DOMAIN:
        domain = ""
    label = domain or "any domain in this workspace"
    print_info(f"Saving a cleanup account for {mark_sensitive(label, 'domain')}.")
    answer = ask_for_cleanup_account(shell)
    if answer is None:
        print_info("Nothing was saved.")
        return
    save_cleanup_account(shell, username=answer[0], secret=answer[1], domain=domain)


def _clear(shell: Any, target: Optional[str]) -> None:
    domain: Optional[str]
    if target is None or target.lower() == "all":
        domain = None
    else:
        domain = "" if target == ANY_DOMAIN else target
    removed = remove_cleanup_accounts(shell, domain=domain)
    if removed:
        names = ", ".join(mark_sensitive(r, "domain") for r in removed)
        print_success(f"Cleanup account removed from this workspace ({names}).")
    else:
        print_info("No saved cleanup account matched; nothing was removed.")
    print_info(f"Add one again at any time with '{CLEANUP_COMMAND} set'.")
