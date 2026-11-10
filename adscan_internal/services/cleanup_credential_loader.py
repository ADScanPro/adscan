"""Where the client cleanup account comes from, and how the operator manages it.

Sources, one store (:mod:`cleanup_credential_store`):

* ``adscan ci`` and the Enterprise worker: the scan configuration's
  ``cleanup_credential`` section names the principal and the ``ADSCAN_*``
  environment variable that holds the secret (the web keeps the secret
  write-only and the worker passes it in that variable, never in a file).
* Any run without that section: ``ADSCAN_CLEANUP_USERNAME`` +
  ``ADSCAN_CLEANUP_SECRET`` (+ optional ``ADSCAN_CLEANUP_DOMAIN``).
* The workspace: an account the operator saved, from the ``start`` question
  (asked once per workspace, default No) or the ``cleanup_credential`` command.
  A run that passes no account for a domain uses the saved one, and says so.

This module is one of the few allowed importers of the store (the others are
the revert cascade, the only reader of the secret, and the workspace save/load
seam, which only moves the store's own serialization).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import mark_sensitive, print_exception, print_info, print_warning
from adscan_internal.services import cleanup_credential_store as _store

__all__ = [
    "CLEANUP_COMMAND",
    "CleanupAccountRow",
    "load_cleanup_credential_for_run",
    "offer_cleanup_credential_prompt",
    "cleanup_account_principal",
    "cleanup_account_identity",
    "cleanup_account_supplied",
    "describe_cleanup_accounts",
    "ask_for_cleanup_account",
    "save_cleanup_account",
    "remove_cleanup_accounts",
    "ANY_DOMAIN",
]

#: The REPL command that manages the saved account (named in operator hints).
CLEANUP_COMMAND = "cleanup_credential"
ANY_DOMAIN = _store.ANY_DOMAIN

_MANAGE_HINT = (
    f"Change it with '{CLEANUP_COMMAND} set', remove it with '{CLEANUP_COMMAND} clear'."
)


@dataclass(frozen=True)
class CleanupAccountRow:
    """One cleanup account as the operator sees it (never the secret)."""

    domain: str
    principal: str
    origin: str


def _domain_label(key: str) -> str:
    return "any domain" if key == ANY_DOMAIN else key


def _save_workspace(shell: Any) -> bool:
    """Persist the store's state through the normal workspace save."""
    saver = getattr(shell, "save_workspace_data", None)
    if not callable(saver) or not getattr(shell, "current_workspace_dir", None):
        return False
    try:
        return bool(saver())
    except Exception as exc:  # noqa: BLE001 - a failed save is reported, not raised
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def load_cleanup_credential_for_run(shell: Any) -> bool:
    """Load the account a non-interactive run references, or fall back to the saved one.

    Call once the workspace is open, so the saved account has been restored.
    Never raises.
    """
    loaded = False
    try:
        reference: Optional[_store.CleanupCredentialReference] = getattr(
            getattr(shell, "scan_config", None), "cleanup_credential", None
        )
        if reference is not None:
            loaded = _store.load_from_reference(reference)
        else:
            loaded = _store.load_from_environment()
    except Exception as exc:  # noqa: BLE001 - a cleanup account never blocks a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    try:
        passed = _store.run_provided_principals()
        for key, principal in _store.saved_workspace_principals().items():
            if key in passed or ANY_DOMAIN in passed:
                continue
            print_info(
                "No cleanup account was passed with this run for "
                f"{mark_sensitive(_domain_label(key), 'domain')}; using the one saved in "
                f"this workspace: {mark_sensitive(principal, 'user')}. It is used only to "
                "undo ADscan's changes, never for the assessment."
            )
            loaded = True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    _refresh_policy(shell)
    return loaded


def _refresh_policy(shell: Any) -> None:
    """Re-resolve the active scan policy for the account now available.

    The checks whose change only a cleanup account can undo run, under a policy
    that allows no manual cleanup, only while one is supplied; the gates follow
    the account without a second source of truth.
    """
    try:
        from adscan_internal.services.revert_permission import (  # noqa: PLC0415
            refresh_policy_revert_permission,
        )

        refresh_policy_revert_permission(shell)
    except Exception as exc:  # noqa: BLE001 - the previous resolution stays in force
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def cleanup_account_principal(domain: str) -> Optional[str]:
    """The cleanup principal configured for ``domain`` (not a secret)."""
    return _store.cleanup_principal(domain)


def cleanup_account_identity(domain: str) -> Optional[tuple[str, str]]:
    """``(principal, home domain)`` of the cleanup account for ``domain`` (no secret)."""
    return _store.cleanup_identity(domain)


def cleanup_account_supplied() -> bool:
    """Whether a cleanup account is configured for any domain of the run."""
    return bool(_store.configured_domains())


def _announce_saved(domain: str) -> None:
    principal = _store.cleanup_principal(domain) or ""
    print_info(
        f"Cleanup account: {mark_sensitive(principal, 'user')} (saved in this "
        f"workspace). {_MANAGE_HINT}"
    )


def ask_for_cleanup_account(shell: Any, *, default_username: str = "") -> Optional[tuple[str, str]]:
    from adscan_core.output import prompt_ask  # noqa: PLC0415

    username = prompt_ask(
        "Cleanup account (sAMAccountName)", default=default_username or None, shell=shell
    ).strip()
    if not username:
        return None
    secret = prompt_ask("Cleanup account password or NT hash", password=True, shell=shell)
    if not secret:
        print_warning("No secret entered; the cleanup account was not saved.")
        return None
    return username, secret


def offer_cleanup_credential_prompt(shell: Any, *, domain: str) -> bool:
    """Ask, once per workspace, whether the operator has a cleanup-only account.

    Runs in ``start unauth`` and ``start auth`` before any attack step can change
    the directory. Default No. Skipped in non-interactive runs (their account
    comes from the scan configuration), when automatic reversion is off (nothing
    would use it), and when this workspace already answered: an account saved for
    ``domain`` is announced in one line, a recorded No stays quiet. Returns
    whether a cleanup account is available for ``domain``.
    """
    from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

    try:
        if _store.has_cleanup_credential(domain):
            if _store.cleanup_source(domain) == _store.SOURCE_WORKSPACE and not getattr(
                shell, "_cleanup_credential_announced", False
            ):
                _announce_saved(domain)
                setattr(shell, "_cleanup_credential_announced", True)
            return True
        if _store.workspace_prompt_answered():
            hinted = getattr(shell, "_cleanup_credential_hinted", None)
            if not isinstance(hinted, set):
                hinted = set()
                setattr(shell, "_cleanup_credential_hinted", hinted)
            if not _store.prompt_declined() and _store_key(domain) not in hinted:
                hinted.add(_store_key(domain))
                print_info(
                    "No cleanup account is saved for "
                    f"{mark_sensitive(domain, 'domain')}. Add one with "
                    f"'{CLEANUP_COMMAND} set {mark_sensitive(domain, 'domain')}'."
                )
            return False
        if getattr(shell, "_cleanup_credential_prompted", False):
            return False
        setattr(shell, "_cleanup_credential_prompted", True)
        if is_non_interactive(shell):
            return False
        from adscan_internal.services.durable_change_policy import (  # noqa: PLC0415
            resolve_auto_revert,
        )

        if not resolve_auto_revert(shell).enabled:
            return False
        from adscan_core.output import confirm_ask  # noqa: PLC0415

        print_info(
            "ADscan reverts the changes it makes in the directory. If your client "
            "provided an account reserved for that cleanup (for example one allowed "
            "only to delete computer objects), ADscan uses it first and never for "
            "the assessment. It is saved in this workspace, so you are asked once."
        )
        if not confirm_ask("Provide a cleanup-only account now?", default=False):
            _store.record_prompt_declined()
            _save_workspace(shell)
            print_info(
                f"Not asked again in this workspace. Add one later with '{CLEANUP_COMMAND} set'."
            )
            return False
        answer = ask_for_cleanup_account(shell)
        if answer is None:
            return False
        return save_cleanup_account(shell, username=answer[0], secret=answer[1], domain=domain)
    except Exception as exc:  # noqa: BLE001 - a cleanup account never blocks a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def save_cleanup_account(shell: Any, *, username: str, secret: str, domain: str) -> bool:
    """Save the account in the workspace and write it to disk. Returns success."""
    if not _store.save_workspace_credential(username=username, secret=secret, domain=domain):
        print_warning("The cleanup account needs a username and a secret; nothing was saved.")
        return False
    target = _domain_label(_store_key(domain))
    if _save_workspace(shell):
        print_info(
            f"Cleanup account {mark_sensitive(username, 'user')} saved in this workspace "
            f"for {mark_sensitive(target, 'domain')}. ADscan uses it only to undo its own "
            "changes, never for the assessment."
        )
    else:
        print_warning(
            f"Cleanup account {mark_sensitive(username, 'user')} is held for this session, "
            "but the workspace could not be saved, so it will be asked for again."
        )
    _refresh_policy(shell)
    return True


def _store_key(domain: str) -> str:
    return str(domain or "").strip().lower() or ANY_DOMAIN


def remove_cleanup_accounts(shell: Any, *, domain: Optional[str] = None) -> list[str]:
    """Delete the saved account(s) from the workspace and from memory.

    The workspace keeps the answer, so the ``start`` question stays quiet; the
    operator can add an account again with the command. Returns the domain keys
    removed from the workspace.
    """
    removed = _store.forget_workspace_credentials(domain)
    if not _store.saved_workspace_principals():
        _store.record_prompt_declined()
    _save_workspace(shell)
    _refresh_policy(shell)
    return removed


def describe_cleanup_accounts() -> list[CleanupAccountRow]:
    """Every cleanup account available now, without secrets, for ``show``."""
    rows: list[CleanupAccountRow] = []
    passed = _store.run_provided_principals()
    for key, principal in _store.saved_workspace_principals().items():
        origin = "Saved in this workspace"
        if key in passed:
            origin += " (this run passed another one, which is used first)"
        rows.append(CleanupAccountRow(_domain_label(key), principal, origin))
    for key, (principal, _source) in passed.items():
        rows.append(CleanupAccountRow(_domain_label(key), principal, "Passed with this run"))
    return rows
