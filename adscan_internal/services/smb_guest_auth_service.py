"""The SMB guest identity: one transport name per engagement that no account carries.

A guest SMB session is requested by signing in with a NAME and no password; a
server with guest access maps any name it does not know to its guest account.
Which name is sent matters: if an account carries it, the sign-in is a failed
sign-in on that account (``badPwdCount`` + 1), not a guest session. The name
used to be the fixed literal ``ADscan``, so a client directory with an account
of that name took a failed sign-in from every guest probe.

This module is the single source of truth for that name and for the guest
session config every SMB guest caller uses:

* :func:`resolve_smb_guest_username` - the name. An operator override wins
  (``domains_data[domain]["guest_username"]``, ``shell.smb_guest_username``,
  ``ADSCAN_SMB_GUEST_USERNAME``, in that order); otherwise ``adscan-`` plus
  eight random hex characters, generated once per LOGICAL workspace and
  persisted in it (``smb_guest_identity.json``; a web scan's execution
  workspace reads and writes the logical workspace's copy), so a client's logs
  show one attributable name per engagement.
* :func:`authorize_smb_guest_identity` - before a guest sign-in in a realm,
  establish that no account carries the name and declare it to the lockout
  guard (rule 6 of ``adscan_core.auth_attempt_guard``). The answer per case is
  stated in :func:`authorize_smb_guest_identity`.
* :func:`build_smb_guest_config` - the ``SMBConfig`` of a guest session
  (``guest_session=True``), declared once here so no call site sets a flag by
  hand.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from adscan_core import auth_attempt_guard as guard
from adscan_core.rich_output import print_info_debug
from adscan_internal.rich_output import mark_sensitive

#: Prefix of every generated guest transport name. No directory convention uses
#: it, and it makes the name attributable to ADscan in the client's logs.
GUEST_NAME_PREFIX = "adscan-"
#: Workspace file that keeps the generated name and the per-realm verdicts.
GUEST_IDENTITY_FILENAME = "smb_guest_identity.json"
_GUEST_IDENTITY_SCHEMA = 2
_GENERATED_NAME_RE = re.compile(r"^adscan-[0-9a-f]{8}$")
#: A generated name found to exist is replaced; three collisions in a row
#: cannot happen by chance, so the third stops instead of looping.
_MAX_GENERATION_ATTEMPTS = 3
#: Refused guest sign-ins a real environment sends before it stops asking, when
#: the name's absence is NOT proven by the KDC (the guard ignores the bound for
#: a ``kerberos`` basis: such a refusal moves no counter on any account). A
#: refusal (``STATUS_LOGON_FAILURE``) cannot tell "guest disabled on this host"
#: from "an account with a password carries this name", so an unconfirmed name
#: costs at most this many failed sign-ins on an account that carried it. Hosts
#: after the bound are a declared coverage gap (``guest_access_coverage``).
GUEST_FAILURE_BOUND_REAL = 3

_GUEST_ALIAS_VALUES = {"guest", "anonymous"}

#: Name used when there is no workspace (one per process).
_PROCESS_GUEST_NAME: Optional[str] = None
_STORE_LOCK = threading.Lock()

#: How a name's absence was established (``GuestIdentity.basis``).
BASIS_DIRECTORY = "directory"
BASIS_KERBEROS = "kerberos"
BASIS_RANDOM = "random"

_NO_REALM_REASON = (
    "no domain was given, so the server would check the name against its own local "
    "accounts, which no directory or Kerberos answer covers"
)


@dataclass(frozen=True)
class GuestIdentity:
    """The guest transport name for one realm and whether it may be sent.

    Attributes:
        name: The transport name.
        generated: True for the per-workspace random name, False for an override.
        declared: True when the lockout guard will let the guest sign-in through.
        basis: How absence was established (``directory``, ``kerberos``,
            ``random``, ``session``), empty when not declared.
        reason: Why the name may not be sent, empty when declared.
    """

    name: str
    generated: bool
    declared: bool
    basis: str = ""
    reason: str = ""


def is_guest_alias(username: str | None) -> bool:
    """Return True when username represents a guest/anonymous logical identity."""
    lowered = str(username or "").strip().lower()
    return lowered in _GUEST_ALIAS_VALUES


def generate_guest_transport_name() -> str:
    """A fresh guest transport name: ``adscan-`` plus 32 random bits in hex."""
    return f"{GUEST_NAME_PREFIX}{secrets.token_hex(4)}"


def is_generated_guest_name(username: str | None) -> bool:
    """True for a name this module generates (never a client account by design)."""
    return bool(_GENERATED_NAME_RE.match(str(username or "").strip().lower()))


def is_credential_less_reader_identity(
    username: str | None,
    *,
    shell: Any | None = None,
    domain: str | None = None,
) -> bool:
    """Return True when ``username`` names a credential-less (guest/null) reader.

    The reading identity of a scan is what actually authenticated the SMB bind
    that read a file — it is NOT the same thing as "an ambient credential-less
    scope happens to be open somewhere above on the call stack" (a scope that
    can legitimately outlive the guest read it was opened for, when the
    downstream credential-hunt chain re-authenticates as a newly-recovered
    domain user and reads further shares synchronously inside it).

    A reader identity is credential-less when it is one of:

    * Empty/blank/``None`` — a null/anonymous SMB session carries no username.
    * A literal guest alias (:func:`is_guest_alias`: ``"guest"``/``"anonymous"``).
    * Any name this module generates (:func:`is_generated_guest_name`), so a
      read done under an EARLIER generated name (replaced, or from another
      process) is never reported as an authenticated principal.
    * The guest transport name for this domain (:func:`resolve_smb_guest_username`).

    Any other value is a real, authenticated domain (or local) principal, so
    it returns ``False``.
    """
    text = str(username or "").strip()
    if not text:
        return True
    if is_guest_alias(text) or is_generated_guest_name(text):
        return True
    guest_username = resolve_smb_guest_username(shell=shell, domain=domain)
    return text.lower() == guest_username.strip().lower()


def is_guest_sign_in_request(
    username: str | None,
    credential: str | None,
    *,
    shell: Any | None = None,
    domain: str | None = None,
) -> bool:
    """True when ``(username, credential)`` asks for a GUEST session.

    A guest session is a guest identity with no credential: the ``guest`` /
    ``anonymous`` alias, a name this module generated, or this domain's guest
    transport name. Callers pass the TRANSPORT name as often as the alias (the
    guest share enumeration hands its own ``adscan-<8 hex>`` name to everything
    it starts), so every seam that decides "is this the guest sign-in" asks
    here. A seam that only recognised the alias sent the transport name to the
    lockout guard as an ordinary account with an empty secret, which rule 4
    refuses although rule 6 allows the declared guest sign-in.

    An empty name is a null session, never a guest one.
    """
    name = str(username or "").strip()
    if not name or str(credential or "").strip():
        return False
    return is_credential_less_reader_identity(name, shell=shell, domain=domain)


# --------------------------------------------------------------------------- name


def _override_name(shell: Any | None, domain: str | None) -> str:
    """The operator's guest username override, or ``""`` (resolution order kept)."""
    if shell is not None and domain:
        domains_data = getattr(shell, "domains_data", None)
        domain_data = domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        if isinstance(domain_data, dict):
            domain_override = str(domain_data.get("guest_username", "") or "").strip()
            if domain_override:
                return domain_override
    if shell is not None:
        shell_override = str(getattr(shell, "smb_guest_username", "") or "").strip()
        if shell_override:
            return shell_override
    return os.getenv("ADSCAN_SMB_GUEST_USERNAME", "").strip()


def _override_problem(name: str) -> str:
    """Why an override cannot be a guest name, or ``""``.

    A domain prefix, a realm suffix or a trailing ``$`` names a SPECIFIC
    account (a qualified user, a UPN, a computer account) that the existence
    checks, which work on bare user names, cannot vouch for.
    """
    if "\\" in name or "@" in name or "/" in name or name.endswith("$"):
        return (
            f"the configured guest username {mark_sensitive(name, 'user')} must be a bare "
            "name: a domain prefix, a realm suffix or a trailing $ names a specific "
            "account, so the guest sign-in is not sent"
        )
    return ""


def _workspace_dir(shell: Any | None) -> str:
    """The active workspace directory, or ``""`` when there is none (never the CWD)."""
    if shell is None:
        return ""
    getter = getattr(shell, "_get_workspace_cwd", None)
    if callable(getter) and getattr(shell, "current_workspace_dir", None):
        try:
            return str(getter() or "")
        except Exception:  # noqa: BLE001 - no workspace is a valid state here
            return ""
    return str(getattr(shell, "current_workspace_dir", "") or "")


def _store_paths(shell: Any | None) -> list[str]:
    """Where the identity lives: the LOGICAL workspace first, then the active one.

    A live web scan runs in an execution workspace (``.run_<logical>_<scanid>``)
    that is not seeded from the logical one, so the identity is read from, and
    written back to, the logical workspace through the execution-workspace SSOT
    (``adscan_core.execution_workspace``). One name per logical workspace.
    """
    workspace = _workspace_dir(shell)
    if not workspace:
        return []
    paths: list[str] = []
    root = Path(workspace)
    try:
        from adscan_core.execution_workspace import (  # noqa: PLC0415
            declared_logical_workspace,
            is_execution_workspace_name,
            resolve_logical_workspace_name,
        )

        if is_execution_workspace_name(root.name):
            logical = declared_logical_workspace(root) or resolve_logical_workspace_name(root.name)
            logical_root = root.parent / logical
            if logical and logical_root.is_dir() and logical_root != root:
                paths.append(str(logical_root / GUEST_IDENTITY_FILENAME))
    except Exception:  # noqa: BLE001 - the active workspace still works on its own
        pass
    paths.append(str(root / GUEST_IDENTITY_FILENAME))
    return paths


def _read_json(path: str) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_store(shell: Any | None) -> dict[str, Any]:
    """The first readable store (logical workspace first)."""
    for path in _store_paths(shell):
        data = _read_json(path)
        if data:
            return data
    return {}


def _save_store(shell: Any | None, data: dict[str, Any]) -> None:
    try:
        from adscan_internal.workspaces import write_json_file  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return
    for path in _store_paths(shell):
        try:
            write_json_file(path, data)
        except Exception as exc:  # noqa: BLE001 - the name still works for this process
            print_info_debug(f"smb guest identity: could not persist ({type(exc).__name__})")


def _empty_store(name: str) -> dict[str, Any]:
    return {"schema": _GUEST_IDENTITY_SCHEMA, "name": name, "realms": {}, "accounts": {}}


def _current_generated_name(shell: Any | None, *, replace: bool = False) -> str:
    """The workspace's generated name (created on first use, or replaced on request)."""
    global _PROCESS_GUEST_NAME  # noqa: PLW0603 - process fallback without a workspace
    with _STORE_LOCK:
        if not _store_paths(shell):
            if replace or not _PROCESS_GUEST_NAME:
                _PROCESS_GUEST_NAME = generate_guest_transport_name()
            return _PROCESS_GUEST_NAME
        store = _load_store(shell)
        name = str(store.get("name") or "").strip()
        if replace or not is_generated_guest_name(name):
            name = generate_guest_transport_name()
            accounts = store.get("accounts") if isinstance(store.get("accounts"), dict) else {}
            store = _empty_store(name)
            store["accounts"] = accounts  # what is known to be an account stays known
            _save_store(shell, store)
        return name


def resolve_smb_guest_username(
    *,
    shell: Any | None = None,
    domain: str | None = None,
) -> str:
    """Resolve the SMB username a guest session sends.

    Resolution order:
    1. Per-domain override: ``domains_data[domain]["guest_username"]``.
    2. Shell-level override: ``shell.smb_guest_username``.
    3. Environment override: ``ADSCAN_SMB_GUEST_USERNAME``.
    4. The logical workspace's generated name (``adscan-<8 hex>``).

    Resolving a name sends nothing; :func:`authorize_smb_guest_identity` decides
    whether it may be sent.
    """
    return _override_name(shell, domain) or _current_generated_name(shell)


# --------------------------------------------------------------------------- evidence


def _is_lab_environment(shell: Any | None) -> bool:
    """Whether the lockout rules in force are a lab's (no guest failure bound,
    no Kerberos exchange spent on the generated name).

    Read from the same source as the lockout guard's budget
    (``resolve_password_attempt_rules``), so the guest rules and the guard can
    never disagree about the environment. Unknown is treated as real.
    """
    if shell is None:
        return False
    try:
        from adscan_core.scan_policy.policy import ENVIRONMENT_LAB  # noqa: PLC0415
        from adscan_internal.services.spray_policy_service import (  # noqa: PLC0415
            resolve_password_attempt_rules,
        )

        return resolve_password_attempt_rules(shell).environment == ENVIRONMENT_LAB
    except Exception:  # noqa: BLE001 - unknown environment is treated as real
        return False


def _domain_file(shell: Any, domain: str, *parts: str) -> str:
    workspace = _workspace_dir(shell)
    if not workspace:
        return ""
    domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains")
    return os.path.join(workspace, domains_dir, domain, *parts)


def _names_in_text_list(path: str) -> set[str]:
    if not path or not os.path.exists(path):
        return set()
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            return {guard.normalize_principal(line) for line in handle if line.strip()}
    except OSError:
        return set()


def _inventory_names(shell: Any | None, domain: str) -> Optional[set[str]]:
    """Normalized sAMAccountNames of the user inventory, ``None`` when there is none."""
    path = _domain_file(shell, domain, "inventory", "users.json") if shell is not None else ""
    payload = _read_json(path)
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list) or not records:
        return None
    names: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        properties = record.get("properties") if isinstance(record.get("properties"), dict) else {}
        sam = str(record.get("samaccountname") or properties.get("samaccountname") or "")
        if sam.strip():
            names.add(guard.normalize_principal(sam))
    return names


#: RID of the built-in Guest account in every domain.
_BUILTIN_GUEST_RID = 501


def _record_rid(record: dict[str, Any]) -> Optional[int]:
    """The RID an inventory record carries (``rid`` or the SID's last part)."""
    properties = record.get("properties") if isinstance(record.get("properties"), dict) else {}
    rid = record.get("rid")
    if isinstance(rid, int):
        return rid
    sid = str(
        record.get("object_id")
        or record.get("objectid")
        or properties.get("objectid")
        or properties.get("objectsid")
        or ""
    ).strip()
    tail = sid.rsplit("-", 1)[-1] if sid.upper().startswith("S-1-5-21-") else ""
    return int(tail) if tail.isdigit() else None


def is_builtin_guest_account(
    shell: Any | None, *, domain: str | None, username: str | None
) -> bool:
    """True when ``username`` is the domain's built-in Guest account (RID 501).

    Decided from directory data: the authenticated user inventory, then the
    unauthenticated one (RID cycling), each of which carries the account's RID.
    An account either inventory lists under another RID is not the built-in
    Guest, whatever it is called. Only when no inventory lists the account does
    the name decide, against the account's default name (``Guest``): a renamed
    or localized Guest that no inventory lists is then treated as an ordinary
    account, which costs one withheld verification and never a sign-in.
    """
    name = guard.normalize_principal(str(username or ""))
    if not name:
        return False
    if shell is not None and domain:
        payload = _read_json(_domain_file(shell, domain, "inventory", "users.json"))
        records = payload.get("records") if isinstance(payload, dict) else None
        sources: list[Any] = [records if isinstance(records, list) else []]
        unauth_path = _domain_file(shell, domain, "users.json")
        try:
            with open(unauth_path, encoding="utf-8") as handle:
                unauth = json.load(handle)
        except (OSError, ValueError):
            unauth = []
        sources.append(unauth if isinstance(unauth, list) else [])
        for records_list in sources:
            for record in records_list:
                if not isinstance(record, dict):
                    continue
                properties = (
                    record.get("properties") if isinstance(record.get("properties"), dict) else {}
                )
                sam = str(record.get("samaccountname") or properties.get("samaccountname") or "")
                if guard.normalize_principal(sam) != name:
                    continue
                rid = _record_rid(record)
                if rid is not None:
                    return rid == _BUILTIN_GUEST_RID
    return name == "guest"


def _realm_key(domain: str) -> str:
    return str(domain or "").strip().rstrip(".").upper()


def _known_account(shell: Any | None, domain: str, name: str) -> bool:
    """True when ANY evidence names ``name`` as an account in ``domain``.

    Read on every authorization, before any saved "absent" verdict: a user list
    (any list proves existence when it names the account), the user inventory,
    the workspace's record of names found to be accounts, and the guard's own
    session knowledge.
    """
    normalized = guard.normalize_principal(name)
    if guard.guest_identity_known_to_exist(domain, name):
        return True
    if shell is not None and domain:
        for filename in ("users.txt", "enabled_users.txt"):
            if normalized in _names_in_text_list(_domain_file(shell, domain, filename)):
                return True
        inventory = _inventory_names(shell, domain)
        if inventory is not None and normalized in inventory:
            return True
    accounts = _load_store(shell).get("accounts")
    realm_accounts = accounts.get(_realm_key(domain)) if isinstance(accounts, dict) else None
    return isinstance(realm_accounts, list) and normalized in realm_accounts


def _remember_account(shell: Any | None, realm: str, name: str) -> None:
    """Persist that ``name`` is an account in ``realm`` (the guard's exists sink)."""
    if not _store_paths(shell):
        return
    with _STORE_LOCK:
        store = _load_store(shell) or _empty_store(str(_load_store(shell).get("name") or ""))
        accounts = store.get("accounts") if isinstance(store.get("accounts"), dict) else {}
        realm_accounts = list(accounts.get(_realm_key(realm)) or [])
        normalized = guard.normalize_principal(name)
        if normalized not in realm_accounts:
            realm_accounts.append(normalized)
        accounts[_realm_key(realm)] = realm_accounts
        store["accounts"] = accounts
        realms = store.get("realms") if isinstance(store.get("realms"), dict) else {}
        entry = realms.get(_realm_key(realm))
        if isinstance(entry, dict) and guard.normalize_principal(str(entry.get("name") or "")) == normalized:
            realms.pop(_realm_key(realm), None)
        store["realms"] = realms
        _save_store(shell, store)


def _probe_kerberos_existence(shell: Any | None, *, domain: str, username: str) -> Optional[bool]:
    """Ask the domain's KDC whether an account carries ``username`` (no secret sent)."""
    if shell is None or not domain:
        return None
    try:
        from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
        from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
        from adscan_internal.services.kerberos_transport import (  # noqa: PLC0415
            probe_principal_existence,
        )

        domains_data = getattr(shell, "domains_data", None)
        domain_data = domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        kdc_ip = resolve_dc_ip(domain_data) if isinstance(domain_data, dict) else None
        if not kdc_ip:
            return None
        return run_async_sync(
            probe_principal_existence(kdc_ip=str(kdc_ip), realm=domain, username=username),
            timeout=20,
        )
    except Exception as exc:  # noqa: BLE001 - an unanswered question is "unknown"
        print_info_debug(f"smb guest identity: existence probe failed ({type(exc).__name__})")
        return None


def _cached_absence(shell: Any | None, domain: str, name: str) -> str:
    """The persisted basis when this workspace already proved ``name`` absent in ``domain``."""
    store = _load_store(shell)
    realms = store.get("realms") if isinstance(store.get("realms"), dict) else {}
    entry = realms.get(_realm_key(domain)) if isinstance(realms, dict) else None
    if (
        isinstance(entry, dict)
        and guard.normalize_principal(str(entry.get("name") or "")) == guard.normalize_principal(name)
        and entry.get("verdict") == "absent"
    ):
        return str(entry.get("basis") or "")
    return ""


def _remember_absence(shell: Any | None, domain: str, name: str, basis: str) -> None:
    if basis not in (BASIS_DIRECTORY, BASIS_KERBEROS) or not _store_paths(shell):
        return
    with _STORE_LOCK:
        store = _load_store(shell) or _empty_store(name)
        realms = store.get("realms") if isinstance(store.get("realms"), dict) else {}
        realms[_realm_key(domain)] = {"name": name, "verdict": "absent", "basis": basis}
        store["realms"] = realms
        _save_store(shell, store)


# --------------------------------------------------------------------------- authorization


def _exists_reason(name: str) -> str:
    return (
        f"the configured guest username {mark_sensitive(name, 'user')} is an account in this "
        "domain, so a sign-in with no password would be a failed sign-in on it; unset the "
        "override to use the engagement's generated guest name"
    )


def _unknown_override_reason(name: str) -> str:
    return (
        f"the configured guest username {mark_sensitive(name, 'user')} names a specific "
        "account and its absence could not be established (only the domain controller's "
        "Kerberos service can prove that a name is not an account), so the guest sign-in "
        "is not sent"
    )


def _refuse(realm: str, name: str, generated: bool, reason: str) -> GuestIdentity:
    guard.refuse_guest_identity(realm, name, reason)
    return GuestIdentity(name, generated, False, reason=reason)


def _declare(shell: Any | None, realm: str, name: str, generated: bool, basis: str) -> GuestIdentity:
    bound = None if _is_lab_environment(shell) else GUEST_FAILURE_BOUND_REAL
    try:
        guard.declare_guest_identity(realm, name, basis=basis, failure_bound=bound)
    except guard.AuthAttemptRefused as refused:
        return _refuse(realm, name, generated, refused.reason)
    _remember_absence(shell, realm, name, basis)
    return GuestIdentity(name, generated, True, basis=basis)


def _authorize_override(shell: Any | None, realm: str, name: str) -> GuestIdentity:
    """An operator's name: refused unless the KDC proved it is not an account.

    * a domain prefix, realm suffix or trailing ``$``        -> refused.
    * any list, the inventory or the session names it        -> refused (exists).
    * the KDC answered "unknown principal" (now or earlier), and the live
      ``badPwdCount`` read does not return it as an account   -> declared.
    * anything else (no KDC answer)                          -> refused: the user
      inventory holds users only and may be capped, so its silence proves nothing
      about a specific name.
    """
    problem = _override_problem(name)
    if problem:
        return _refuse(realm, name, False, problem)
    if _known_account(shell, realm, name):
        if guard.is_declared_guest(realm, name):
            guard.record_guest_identity_exists(realm, name, _exists_reason(name))
        return _refuse(realm, name, False, _exists_reason(name))
    if guard.is_declared_guest(realm, name):
        return GuestIdentity(name, False, True, basis="session")
    basis = _cached_absence(shell, realm, name)
    if basis != BASIS_KERBEROS:
        verdict = _probe_kerberos_existence(shell, domain=realm, username=name)
        if verdict is True:
            guard.record_guest_identity_exists(realm, name, _exists_reason(name))
            return _refuse(realm, name, False, _exists_reason(name))
        if verdict is None:
            return _refuse(realm, name, False, _unknown_override_reason(name))
        basis = BASIS_KERBEROS
    if guard.principal_known_by_live_read(realm, name):
        guard.record_guest_identity_exists(realm, name, _exists_reason(name))
        return _refuse(realm, name, False, _exists_reason(name))
    return _declare(shell, realm, name, False, basis)


def _authorize_generated(shell: Any | None, realm: str) -> GuestIdentity:
    """The workspace's random name.

    * any list, the inventory or the session names it -> replaced by a new name.
    * in a real environment the KDC is asked first (once per workspace and
      realm): "unknown principal" -> declared (``kerberos``), the only basis the
      guest failure bound never applies to, so guest coverage is not cut short;
      "exists" -> replaced.
    * no KDC answer (or a lab), the user inventory exists and does not name it
      -> declared (``directory``, bounded).
    * existence unknown -> declared (``random``, bounded): 32 random bits behind
      a prefix no directory uses (see the guard's worst-case note).
    """
    name = _current_generated_name(shell)
    for _attempt in range(_MAX_GENERATION_ATTEMPTS):
        if _known_account(shell, realm, name):
            if guard.is_declared_guest(realm, name):
                guard.record_guest_identity_exists(realm, name, "the directory lists an account with this name")
            print_info_debug(
                f"smb guest identity: {mark_sensitive(name, 'user')} is an account in "
                f"{mark_sensitive(realm, 'domain')}; generating another name"
            )
            name = _current_generated_name(shell, replace=True)
            continue
        if guard.is_declared_guest(realm, name):
            return GuestIdentity(name, True, True, basis="session")
        basis = _cached_absence(shell, realm, name)
        if basis != BASIS_KERBEROS:
            verdict: Optional[bool] = None
            if not _is_lab_environment(shell):
                verdict = _probe_kerberos_existence(shell, domain=realm, username=name)
                if verdict is True:
                    guard.record_guest_identity_exists(realm, name, "the KDC reports an account with this name")
                    name = _current_generated_name(shell, replace=True)
                    continue
            if verdict is False:
                basis = BASIS_KERBEROS
            elif _inventory_names(shell, realm) is not None:
                basis = BASIS_DIRECTORY
            else:
                basis = BASIS_RANDOM
        return _declare(shell, realm, name, True, basis)
    return _refuse(realm, name, True, "no generated guest name could be established")


#: canonical realm -> (shell, domain key) for declaring the guest coverage gap.
_GAP_DOMAINS: dict[str, tuple[Any, str]] = {}


def _declare_guest_gap(realm: str, _name: str, hosts_not_checked: int) -> None:
    """Declare the hosts the guest failure bound left unchecked (the guard's gap sink).

    Stamped into the session's ``domains_data`` and the technical report, from
    which the PDF report, the LITE report and the web platform render the same
    statement (:mod:`adscan_core.reporting.guest_access_coverage`).
    """
    target = _GAP_DOMAINS.get(_realm_key(realm))
    if target is None:
        return
    shell, domain = target
    from adscan_core.reporting.guest_access_coverage import (  # noqa: PLC0415
        GUEST_ACCESS_COVERAGE_KEY,
        build_guest_access_coverage,
    )
    from adscan_core.reporting.technical_report import (  # noqa: PLC0415
        record_guest_access_coverage,
    )

    block = build_guest_access_coverage(hosts_not_checked=hosts_not_checked)
    if not block:
        return
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict):
        entry = domains_data.setdefault(domain, {})
        if isinstance(entry, dict):
            entry[GUEST_ACCESS_COVERAGE_KEY] = block
    if shell is not None:
        record_guest_access_coverage(shell, domain, coverage=block)


def authorize_smb_guest_identity(shell: Any | None, *, domain: str) -> GuestIdentity:
    """Establish the guest name for ``domain`` and declare it to the lockout guard.

    Never raises. When the name may not be sent, the reason is recorded with the
    guard (``refuse_guest_identity``), so the guest sign-in is refused at the
    transport seam with that reason instead of reaching the wire. Evidence that
    the name is an account is always read before any saved "absent" verdict,
    and the guard is told to persist any account it learns about later.
    """
    realm = str(domain or "").strip()
    guard.register_guest_exists_sink(
        lambda found_realm, found_name, _why: _remember_account(shell, found_realm, found_name)
    )
    if realm:
        _GAP_DOMAINS[_realm_key(realm)] = (shell, realm)
        guard.register_guest_gap_sink(_declare_guest_gap)
    override = _override_name(shell, realm)
    if not realm:
        name = override or _current_generated_name(shell)
        return GuestIdentity(name, not override, False, reason=_NO_REALM_REASON)
    if override:
        return _authorize_override(shell, realm, override)
    return _authorize_generated(shell, realm)


def build_smb_guest_config(
    shell: Any | None,
    *,
    domain: str,
    target_ip: str,
    target_hostname: str | None = None,
    timeout: int = 30,
    dns_server: str | None = None,
    port: int = 445,
):
    """The ``SMBConfig`` of a guest session against ``target_ip`` (the only guest builder).

    Authorizes the guest name first (:func:`authorize_smb_guest_identity`); a
    name that may not be sent still yields a config, which the transport's
    lockout guard refuses before the wire with the recorded reason.
    """
    from adscan_internal.services.smb_transport import SMBConfig  # noqa: PLC0415

    identity = authorize_smb_guest_identity(shell, domain=domain)
    return SMBConfig(
        target_ip=target_ip,
        target_hostname=target_hostname,
        domain=domain,
        username=identity.name,
        password="",
        auth_domain=domain,
        use_kerberos=False,
        guest_session=True,
        dns_server=dns_server,
        timeout=timeout,
        port=port,
    )


__all__ = [
    "BASIS_DIRECTORY",
    "BASIS_KERBEROS",
    "BASIS_RANDOM",
    "GUEST_FAILURE_BOUND_REAL",
    "GUEST_IDENTITY_FILENAME",
    "GUEST_NAME_PREFIX",
    "GuestIdentity",
    "authorize_smb_guest_identity",
    "build_smb_guest_config",
    "generate_guest_transport_name",
    "is_builtin_guest_account",
    "is_credential_less_reader_identity",
    "is_generated_guest_name",
    "is_guest_sign_in_request",
    "is_guest_alias",
    "resolve_smb_guest_username",
]
