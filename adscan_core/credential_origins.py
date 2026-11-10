"""Credential provenance values every layer needs to agree on (stdlib only).

``credentials_meta[<user>]["credential_origin"]`` records how a credential
entered the store. The engine, the workspace secret purge and the web backend
all need to tell the scan's own STARTING credential from a credential the
assessment recovered, and the web cannot import the engine, so the set lives
here and the engine re-exports it.

A second kind of credential is not the client's either: the password of an
account ADscan CREATED during the assessment (the scheduled-task escalation's
temporary domain administrator, a provisioned machine account, the database
administrator a SQL escalation mints). ADscan chose that secret, so listing it
as a "recovered" or "compromised" client credential is false, and telling the
client to rotate it is worse: the account was ADscan's, and the change ledger
already reports it as created and (normally) deleted. Two signals identify it,
and every client-facing projection honours both:

* the origin ``adscan_provisioned``, stamped when the credential is stored;
* the environment-change ledger, which names every account ADscan created
  (:data:`ADSCAN_CREATED_ACCOUNT_KINDS`). The ledger is the authoritative record
  and covers workspaces written before the origin existed.

The engine keeps using the credential internally (follow-up steps may need it);
only what a client reads excludes it.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterable, Mapping

#: Origins of a SELF-INTRODUCED credential: the scan's starting credential (the
#: input to ``adscan ci auth`` / ``start_auth``) and one entered by hand
#: (``creds save`` / ``creds add``). Neither was recovered by the assessment.
#: The workspace secret purge KEEPS these on request, and the report resolves the
#: scan's starting identity from them, so an ADscan-created account is NOT here.
NON_COMPROMISE_ORIGINS: frozenset[str] = frozenset({"authenticated_scan", "user_provided"})

#: Origin of the credential of an account ADscan itself created.
ORIGIN_ADSCAN_PROVISIONED = "adscan_provisioned"

#: Every origin whose credential is NOT a client credential the assessment
#: recovered: the self-introduced ones plus ADscan's own provisioned accounts.
#: This is the set a client-facing credential list or count excludes.
NOT_RECOVERED_ORIGINS: frozenset[str] = NON_COMPROMISE_ORIGINS | {ORIGIN_ADSCAN_PROVISIONED}

#: Ledger change kinds that record an account ADscan created.
ADSCAN_CREATED_ACCOUNT_KINDS: frozenset[str] = frozenset(
    {
        "user_created",
        "machine_account_created",
        "computer_account_created",
        "mssql_admin_account_created",
    }
)

#: Detail keys that name the created account, in preference order.
_CREATED_ACCOUNT_DETAIL_KEYS: tuple[str, ...] = (
    "sam",
    "account",
    "target_object",
    "computer_name",
    "sam_account_name",
)

ENVIRONMENT_CHANGES_FILENAME = "environment_changes.json"


def is_recovered_credential_origin(origin: Any) -> bool:
    """True when ``origin`` marks a credential the assessment obtained.

    False for the scan's own starting credential, a manually entered one and the
    credential of an account ADscan created. True for everything else, including
    an unrecorded origin (an account in the store with no provenance was still
    obtained).
    """
    return str(origin or "").strip().lower() not in NOT_RECOVERED_ORIGINS


def normalize_account_name(name: Any) -> str:
    """Lower-cased bare account name: no realm, no NetBIOS qualifier."""
    text = str(name or "").strip().lower()
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text


def _normalize_domain(domain: Any) -> str:
    return str(domain or "").strip().rstrip(".").lower()


def _created_account_name(change: Mapping[str, Any]) -> str:
    detail = change.get("detail")
    detail = detail if isinstance(detail, Mapping) else {}
    for key in _CREATED_ACCOUNT_DETAIL_KEYS:
        value = detail.get(key)
        if isinstance(value, str) and value.strip():
            return normalize_account_name(value)
    target = str(change.get("target") or "").strip()
    # A free-text target ("CASTELBLACK (linked server via ...)", "a -> b") is not
    # an account name; only a bare token is.
    if target and not any(ch in target for ch in " ()>"):
        return normalize_account_name(target)
    return ""


def adscan_created_accounts(changes: Iterable[Any] | None) -> dict[str, frozenset[str]]:
    """Return ``{domain_lower: {account_lower}}`` for every account ADscan created.

    Read from environment-change ledger entries. A change counts when its kind is
    in :data:`ADSCAN_CREATED_ACCOUNT_KINDS` or its detail carries
    ``provisioned_by_adscan``. The revert status does not matter: an account
    ADscan created stays ADscan's whether it was deleted, kept or left for a
    manual cleanup. The domain is the change's ``target_domain`` when recorded,
    else its ``domain``. Never raises.
    """
    out: dict[str, set[str]] = {}
    for change in changes or ():
        if not isinstance(change, Mapping):
            continue
        detail = change.get("detail")
        detail = detail if isinstance(detail, Mapping) else {}
        kind = str(change.get("kind") or "").strip().lower()
        if kind not in ADSCAN_CREATED_ACCOUNT_KINDS and detail.get("provisioned_by_adscan") is not True:
            continue
        name = _created_account_name(change)
        if not name:
            continue
        domain = _normalize_domain(detail.get("target_domain") or change.get("domain"))
        out.setdefault(domain, set()).add(name)
    return {domain: frozenset(names) for domain, names in out.items()}


def ledger_changes(block: Any) -> list[Mapping[str, Any]]:
    """The change entries of a ledger block (``{"changes": [...]}``) or a list."""
    if isinstance(block, Mapping):
        block = block.get("changes")
    if not isinstance(block, list):
        return []
    return [entry for entry in block if isinstance(entry, Mapping)]


def load_adscan_created_accounts(workspace_dir: Any) -> dict[str, frozenset[str]]:
    """Read the workspace ledger and return :func:`adscan_created_accounts` of it.

    Falls back to the ledger block embedded in ``technical_report.json`` when the
    standalone file is absent. Best-effort: an unreadable ledger yields ``{}``.
    """
    root = str(workspace_dir or "")
    if not root:
        return {}
    for name, extract in (
        (ENVIRONMENT_CHANGES_FILENAME, lambda data: data),
        ("technical_report.json", lambda data: data.get("environment_changes") if isinstance(data, Mapping) else None),
    ):
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        changes = ledger_changes(extract(data))
        if changes:
            return adscan_created_accounts(changes)
    return {}


def is_adscan_created_account(
    created: Mapping[str, Iterable[str]] | None, *, domain: Any, account: Any
) -> bool:
    """True when ``account`` of ``domain`` is one ADscan created.

    An entry recorded without a domain matches the account in any domain.
    """
    if not created:
        return False
    name = normalize_account_name(account)
    if not name:
        return False
    return name in (created.get(_normalize_domain(domain)) or ()) or name in (created.get("") or ())


def is_client_recovered_credential(
    *,
    domain: Any,
    account: Any,
    origin: Any,
    created: Mapping[str, Iterable[str]] | None = None,
) -> bool:
    """The one predicate a client-facing credential list or count applies.

    False for a self-introduced credential, for the credential of an account
    ADscan created (by origin or by the ledger), True otherwise.
    """
    if not is_recovered_credential_origin(origin):
        return False
    return not is_adscan_created_account(created, domain=domain, account=account)


def mark_adscan_provisioned_origins(
    domains_data: Mapping[str, Any] | None,
    created: Mapping[str, Iterable[str]] | None,
) -> dict[str, Any]:
    """Return ``domains_data`` with ADscan-created accounts tagged by origin.

    Every account the ledger names as ADscan-created gets
    ``credential_origin = "adscan_provisioned"`` in its ``credentials_meta``, so a
    consumer that only reads the origin excludes it too. Non-mutating: the
    returned mapping shares nothing it changed with the input. A domain without
    such an account is returned as is.
    """
    source = domains_data if isinstance(domains_data, Mapping) else {}
    if not created:
        return dict(source)
    out: dict[str, Any] = {}
    for domain, payload in source.items():
        if not isinstance(payload, Mapping):
            out[domain] = payload
            continue
        credentials = payload.get("credentials")
        meta = payload.get("credentials_meta")
        names = set(credentials) if isinstance(credentials, Mapping) else set()
        names |= set(meta) if isinstance(meta, Mapping) else set()
        hits = [n for n in names if is_adscan_created_account(created, domain=domain, account=n)]
        if not hits:
            out[domain] = payload
            continue
        new_meta = dict(meta) if isinstance(meta, Mapping) else {}
        for name in hits:
            record = new_meta.get(name)
            record = dict(record) if isinstance(record, Mapping) else {}
            record["credential_origin"] = ORIGIN_ADSCAN_PROVISIONED
            new_meta[name] = record
        new_payload = dict(payload)
        new_payload["credentials_meta"] = new_meta
        out[domain] = new_payload
    return out


__all__ = [
    "ADSCAN_CREATED_ACCOUNT_KINDS",
    "ENVIRONMENT_CHANGES_FILENAME",
    "NON_COMPROMISE_ORIGINS",
    "NOT_RECOVERED_ORIGINS",
    "ORIGIN_ADSCAN_PROVISIONED",
    "adscan_created_accounts",
    "is_adscan_created_account",
    "is_client_recovered_credential",
    "is_recovered_credential_origin",
    "ledger_changes",
    "load_adscan_created_accounts",
    "mark_adscan_provisioned_origins",
    "normalize_account_name",
]
