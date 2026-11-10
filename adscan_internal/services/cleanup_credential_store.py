"""The client-provided cleanup credential: its own store, one reader.

A client can hand ADscan an account whose only job is to undo what the
assessment changed in their directory (spec section 8.1; founder decisions
2026-11-05, "Reversion de cambios en el directorio"). That account is NOT an
assessment credential, and the separation of USE is the whole point of this
module:

* It is never written into ``domains_data`` (``credentials``,
  ``kerberos_tickets``, ``local_credentials``, ``service_tickets``), the
  credential store service, or any resolver an attack step or a sweep consults.
  An assessment that reached Tier 0 with the cleanup account would be reporting
  the client's own gift as a compromise.
* It reaches a run in one of two ways. ``adscan ci`` and the Enterprise worker
  pass it by REFERENCE: the scan configuration names an ``ADSCAN_*`` environment
  variable that holds the secret (the launcher forwards ``ADSCAN_*`` into the
  container). Or the operator saves it in the workspace, from the ``start``
  question or the ``cleanup_credential set`` command. A value passed with the
  run wins over the saved one for the same domain, and is never saved.
* The saved account is written ONLY under its own top-level ``variables.json``
  key, :data:`WORKSPACE_VARIABLES_KEY`: the same file, and the same at-rest
  class, as the credentials the assessment captures, but outside
  ``domains_data`` so nothing that walks a domain's data can reach it. Nothing
  but this module reads or writes that key. The workspace save/load seam
  (``workspaces/state.py``) calls :func:`export_workspace_state` and
  :func:`restore_workspace_state` without looking inside, so the at-rest format
  (an encrypted vault, for instance) can change here without touching a caller.
  The telemetry sanitizer also learns the secret, only to mask it.
* Exactly ONE function returns the secret: :func:`get_for_revert`, and exactly
  one module calls it: :mod:`adscan_internal.services.revert_credentials`, the
  cascade every revert executor goes through. Both facts are locked by
  structural tests (``tests/unit/services/test_cleanup_credential_separation.py``).

Everything else in this module returns non-secret facts (the principal, where it
came from), which the report and the ledger may carry.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Mapping, Optional

from adscan_core import telemetry
from adscan_core.rich_output import mark_sensitive, print_info, print_warning
from adscan_internal.services.cleanup_credential_reference import (
    CLEANUP_SECRET_ENV_DEFAULT,
    CleanupCredentialError,
    CleanupCredentialReference,
)
from adscan_internal.services.cleanup_credential_reference import (
    parse_cleanup_reference as parse_reference,
)

__all__ = [
    "CLEANUP_SECRET_ENV_DEFAULT",
    "CLEANUP_USERNAME_ENV",
    "CLEANUP_DOMAIN_ENV",
    "CleanupCredentialReference",
    "ClientCleanupCredential",
    "CleanupCredentialError",
    "SOURCE_SCAN_CONFIG",
    "SOURCE_ENV",
    "SOURCE_PROMPT",
    "SOURCE_WORKSPACE",
    "WORKSPACE_VARIABLES_KEY",
    "ANY_DOMAIN",
    "set_cleanup_credential",
    "save_workspace_credential",
    "forget_workspace_credentials",
    "saved_workspace_principals",
    "record_prompt_declined",
    "prompt_declined",
    "workspace_prompt_answered",
    "clear_cleanup_credentials",
    "export_workspace_state",
    "restore_workspace_state",
    "has_cleanup_credential",
    "cleanup_principal",
    "cleanup_identity",
    "cleanup_source",
    "configured_domains",
    "run_provided_principals",
    "get_for_revert",
    "load_from_reference",
    "load_from_environment",
    "parse_reference",
]

#: Env-only shortcut (no scan configuration): the principal and its domain.
CLEANUP_USERNAME_ENV = "ADSCAN_CLEANUP_USERNAME"
CLEANUP_DOMAIN_ENV = "ADSCAN_CLEANUP_DOMAIN"

SOURCE_SCAN_CONFIG = "scan_config"
SOURCE_ENV = "environment"
SOURCE_PROMPT = "operator_prompt"
#: Saved in the workspace (the ``start`` question or ``cleanup_credential set``).
SOURCE_WORKSPACE = "workspace"

#: The top-level ``variables.json`` key holding the saved cleanup account(s).
#: Mirrored by ``adscan_core.telemetry._CLEANUP_CREDENTIALS_KEY`` (masking only).
WORKSPACE_VARIABLES_KEY = "cleanup_credentials"
_WORKSPACE_STATE_VERSION = 1

#: Any domain the run touches; used when the client supplied one account and
#: did not say which domain it belongs to (a single-domain engagement).
ANY_DOMAIN = "*"


@dataclass(frozen=True)
class ClientCleanupCredential:
    """The cleanup account as handed to a revert executor.

    ``secret`` is excluded from ``repr`` so an accidental log of the object
    never prints it.
    """

    username: str
    domain: str
    source: str
    secret: str = field(repr=False, default="")


_LOCK = threading.Lock()
#: Accounts passed with THIS run (scan configuration, environment). Never saved.
_STORE: dict[str, ClientCleanupCredential] = {}
#: Accounts saved in the active workspace (restored from, and exported to,
#: ``variables.json`` through the two functions below).
_SAVED: dict[str, ClientCleanupCredential] = {}
#: The operator answered No to the ``start`` question in this workspace.
_PROMPT_DECLINED = False


def _domain_key(domain: str) -> str:
    return str(domain or "").strip().lower() or ANY_DOMAIN


def _register_secret_with_telemetry(secret: str) -> None:
    """Keep the secret out of every recording, whatever later prints it."""
    try:
        telemetry.add_known_password(secret)
    except Exception:  # noqa: BLE001 - masking registration is best-effort
        pass


def _make_credential(
    *, username: str, secret: str, domain: str, source: str
) -> Optional[ClientCleanupCredential]:
    user = str(username or "").strip()
    if not user or not secret:
        return None
    _register_secret_with_telemetry(str(secret))
    clean_domain = str(domain or "").strip().lower()
    return ClientCleanupCredential(
        username=user,
        domain="" if clean_domain == ANY_DOMAIN else clean_domain,
        source=source,
        secret=str(secret),
    )


def set_cleanup_credential(
    *, username: str, secret: str, domain: str = "", source: str
) -> bool:
    """Hold the cleanup account for this run only. Returns False when incomplete."""
    cred = _make_credential(username=username, secret=secret, domain=domain, source=source)
    if cred is None:
        return False
    with _LOCK:
        _STORE[_domain_key(domain)] = cred
    return True


def save_workspace_credential(*, username: str, secret: str, domain: str = "") -> bool:
    """Save the cleanup account in the active workspace.

    It reaches ``variables.json`` on the next workspace save. Replaces any
    account saved for the same domain. Returns False when incomplete.
    """
    global _PROMPT_DECLINED
    cred = _make_credential(
        username=username, secret=secret, domain=domain, source=SOURCE_WORKSPACE
    )
    if cred is None:
        return False
    with _LOCK:
        _SAVED[_domain_key(domain)] = cred
        _PROMPT_DECLINED = False
    return True


def forget_workspace_credentials(domain: Optional[str] = None) -> list[str]:
    """Remove the saved account, and any run-held one, for ``domain``.

    ``None`` removes every account. Returns the workspace domain keys removed.
    The caller saves the workspace so the removal reaches disk.
    """
    with _LOCK:
        if domain is None:
            removed = sorted(_SAVED)
            _SAVED.clear()
            _STORE.clear()
            return removed
        key = _domain_key(domain)
        removed = [key] if key in _SAVED else []
        _SAVED.pop(key, None)
        _STORE.pop(key, None)
        return removed


def saved_workspace_principals() -> dict[str, str]:
    """``{domain_key: principal}`` of the accounts saved in the workspace."""
    with _LOCK:
        return {key: cred.username for key, cred in sorted(_SAVED.items())}


def run_provided_principals() -> dict[str, tuple[str, str]]:
    """``{domain_key: (principal, source)}`` of the accounts passed with this run."""
    with _LOCK:
        return {key: (cred.username, cred.source) for key, cred in sorted(_STORE.items())}


def record_prompt_declined() -> None:
    """Remember that the operator answered No in this workspace."""
    global _PROMPT_DECLINED
    with _LOCK:
        _PROMPT_DECLINED = True


def prompt_declined() -> bool:
    """Whether the operator answered No to the ``start`` question here."""
    with _LOCK:
        return _PROMPT_DECLINED


def workspace_prompt_answered() -> bool:
    """Whether this workspace already answered the question (No, or a saved account)."""
    with _LOCK:
        return _PROMPT_DECLINED or bool(_SAVED)


def clear_cleanup_credentials() -> None:
    """Forget every cleanup account and answer held by this process.

    Touches nothing on disk by itself. Code that means to remove a SAVED account
    calls :func:`forget_workspace_credentials` and saves the workspace.
    """
    global _PROMPT_DECLINED
    with _LOCK:
        _STORE.clear()
        _SAVED.clear()
        _PROMPT_DECLINED = False


def export_workspace_state() -> Optional[dict]:
    """The ``variables.json`` value for :data:`WORKSPACE_VARIABLES_KEY`, or ``None``.

    The ONLY writer of the saved secret. ``None`` when the workspace holds
    nothing (no account, no recorded answer), so an untouched workspace's
    ``variables.json`` does not grow the key. Accounts passed with the run are
    never exported.
    """
    with _LOCK:
        if not _SAVED and not _PROMPT_DECLINED:
            return None
        return {
            "version": _WORKSPACE_STATE_VERSION,
            "prompt_declined": bool(_PROMPT_DECLINED),
            "accounts": {
                key: {"username": cred.username, "domain": cred.domain, "secret": cred.secret}
                for key, cred in sorted(_SAVED.items())
            },
        }


def restore_workspace_state(raw: object, *, present: bool, reset: bool) -> None:
    """Load the saved account(s) from a workspace's ``variables.json`` value.

    Args:
        raw: The value under :data:`WORKSPACE_VARIABLES_KEY` (ignored when
            ``present`` is False).
        present: Whether the payload carried the key at all.
        reset: The payload is a full workspace load (switching workspaces). An
            absent key then means "nothing saved here", so the previous
            workspace's accounts are dropped. A partial payload never resets.

    Accounts passed with the run are kept: they belong to the process, not to a
    workspace. A malformed value is ignored, never fatal.
    """
    global _PROMPT_DECLINED
    if not present:
        if reset:
            with _LOCK:
                _SAVED.clear()
                _PROMPT_DECLINED = False
        return
    accounts: dict[str, ClientCleanupCredential] = {}
    declined = False
    if isinstance(raw, Mapping):
        declined = bool(raw.get("prompt_declined"))
        stored = raw.get("accounts")
        if isinstance(stored, Mapping):
            for key, entry in stored.items():
                if not isinstance(entry, Mapping):
                    continue
                cred = _make_credential(
                    username=str(entry.get("username") or ""),
                    secret=str(entry.get("secret") or ""),
                    domain=str(entry.get("domain") or ""),
                    source=SOURCE_WORKSPACE,
                )
                if cred is not None:
                    accounts[_domain_key(str(key))] = cred
    with _LOCK:
        _SAVED.clear()
        _SAVED.update(accounts)
        _PROMPT_DECLINED = declined


def _lookup(domain: str) -> Optional[ClientCleanupCredential]:
    """Run-provided first, then saved; an exact domain before the any-domain one."""
    key = _domain_key(domain)
    with _LOCK:
        return (
            _STORE.get(key)
            or _SAVED.get(key)
            or _STORE.get(ANY_DOMAIN)
            or _SAVED.get(ANY_DOMAIN)
        )


def has_cleanup_credential(domain: str) -> bool:
    """Whether a cleanup account is available for ``domain``."""
    return _lookup(domain) is not None


def cleanup_principal(domain: str) -> Optional[str]:
    """The cleanup principal for ``domain`` (not a secret), or ``None``."""
    found = _lookup(domain)
    return found.username if found else None


def cleanup_identity(domain: str) -> Optional[tuple[str, str]]:
    """``(principal, home domain)`` of the account for ``domain``, never the secret.

    The home domain is the one the account was supplied for, or ``"*"`` when the
    client gave one account without naming its domain.
    """
    found = _lookup(domain)
    if found is None:
        return None
    return found.username, (found.domain or ANY_DOMAIN)


def cleanup_source(domain: str) -> Optional[str]:
    """Where the account used for ``domain`` comes from (``SOURCE_*``), or ``None``."""
    found = _lookup(domain)
    return found.source if found else None


def configured_domains() -> list[str]:
    """Domains a cleanup account is available for (``*`` = any)."""
    with _LOCK:
        return sorted(set(_STORE) | set(_SAVED))


def get_for_revert(*, domain: str, purpose: str) -> Optional[ClientCleanupCredential]:
    """Return the cleanup account for a revert. THE single reader of the secret.

    Only :mod:`adscan_internal.services.revert_credentials` may call this
    (structural test). ``purpose`` names the revert so a future audit trail can
    record why the secret was read; it is never logged with the secret.

    Args:
        domain: The domain of the object being reverted.
        purpose: Short tag of the caller (e.g. the ledger change kind).
    """
    del purpose  # recorded by the caller in the ledger attempt log
    return _lookup(domain)


def load_from_reference(
    reference: Optional[CleanupCredentialReference],
    *,
    environ: Optional[Mapping[str, str]] = None,
) -> bool:
    """Load the cleanup account a scan configuration references.

    Returns True when a credential was loaded. A reference whose environment
    variable is empty is reported (the operator asked for a cleanup account and
    will not get one) and ignored; it never aborts the scan.
    """
    if reference is None:
        return False
    source_env = os.environ if environ is None else environ
    secret = str(source_env.get(reference.secret_env, "") or "")
    if not secret:
        print_warning(
            "A cleanup account was configured but its secret was not provided "
            f"(environment variable {reference.secret_env} is empty). Reverts use the "
            "credentials the assessment holds."
        )
        return False
    loaded = set_cleanup_credential(
        username=reference.username,
        secret=secret,
        domain=reference.domain,
        source=SOURCE_SCAN_CONFIG,
    )
    if loaded:
        print_info(
            "Cleanup account loaded for reverting assessment changes: "
            f"{mark_sensitive(reference.username, 'user')}. It is used only to undo "
            "changes, never for the assessment."
        )
    return loaded


def load_from_environment(*, environ: Optional[Mapping[str, str]] = None) -> bool:
    """Env-only shortcut: ``ADSCAN_CLEANUP_USERNAME`` + ``ADSCAN_CLEANUP_SECRET``."""
    source_env = os.environ if environ is None else environ
    username = str(source_env.get(CLEANUP_USERNAME_ENV, "") or "").strip()
    if not username:
        return False
    return load_from_reference(
        CleanupCredentialReference(
            username=username,
            domain=str(source_env.get(CLEANUP_DOMAIN_ENV, "") or "").strip(),
            secret_env=CLEANUP_SECRET_ENV_DEFAULT,
        ),
        environ=source_env,
    )
