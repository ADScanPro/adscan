"""Persist DCSync dump output as a workspace inventory artefact.

The DCSync flow in :mod:`adscan_internal.cli.secretsdump` builds the
in-memory list of cracked credentials (``raw_credentials``) plus the
post-cracking list (``creds_to_persist``). This helper writes that
material to ``<workspace>/domains/<domain>/inventory/dcsync_dump.json``
so the web ingestion pipeline can build the DCSync Intelligence KPIs.

The file is a per-account REGISTER that ACCUMULATES observations across
runs, not a snapshot of the last run. One domain is replicated more than
once in a normal engagement: a full DRSUAPI walk early on, then narrowly
scoped reruns from attack-path steps that only need one principal (the
``krbtgt`` of an executed DCSync edge, the Domain Admin an ESC path
reached). Replacing the file wholesale on every call made the last,
narrowest run the whole register — a full walk of a four-figure account
count was observed reduced to a single entry, so the platform's DCSync
Intelligence KPIs read a one-account dump for a fully replicated domain.
Replication never proves an account is GONE, so nothing a previous run
observed is dropped; see :func:`write_dcsync_dump_file` for the
per-account precedence rules and for how the register is reset.

Plaintext is **never** persisted, never logged, never returned. The
file contains only the NT hash plus a ``plaintext_recovered`` boolean
flag. Plaintext stays on disk in the cracking history / potfile only.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Iterable

from adscan_internal.workspaces import domain_subpath, write_json_file

INVENTORY_SCHEMA_VERSION = "inventory-1.0"
EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
DUMP_FILENAME = "dcsync_dump.json"


def _extract_rid(sid: str | None) -> int | None:
    if not sid:
        return None
    try:
        return int(str(sid).rsplit("-", 1)[1])
    except (ValueError, IndexError):
        return None


def _is_machine_account(sam: str) -> bool:
    return bool(sam) and sam.endswith("$")


def _normalize_domain(value: str | None) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _normalize_hash(value: Any) -> str:
    return str(value or "").strip().lower()


def _load_recorded_entries(path: str, domain_key: str) -> dict[str, dict]:
    """Return the register already on disk, keyed by lower-cased sAMAccountName.

    Resilient by design: a missing, unreadable, malformed or future-schema file
    yields an empty register, so a previous bad write can never block the
    current one. Rows keyed to a different domain are dropped rather than
    adopted — the register is per-domain, and inheriting a foreign principal
    would attribute it to the wrong directory in the client-facing KPIs.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    if str(payload.get("schema_version") or "") != INVENTORY_SCHEMA_VERSION:
        # A register written by a newer/unknown schema is left unread instead of
        # being half-interpreted against this one's field meanings.
        return {}
    file_domain = _normalize_domain(payload.get("domain")) or domain_key
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        return {}

    recorded: dict[str, dict] = {}
    for raw in raw_entries:
        if not isinstance(raw, dict):
            continue
        sam = str(raw.get("samaccountname") or "").strip()
        nt = _normalize_hash(raw.get("nt_hash"))
        if not sam or not nt:
            continue
        entry_domain = _normalize_domain(raw.get("domain")) or file_domain
        if entry_domain != domain_key:
            continue
        recorded[sam.lower()] = raw
    return recorded


def _merge_entry(previous: dict | None, current: dict) -> dict:
    """Fold a fresh observation of one account onto what was already recorded.

    The fresh observation wins — it is the more recent read of the directory —
    but only where it actually carries information:

    * ``rid`` is an identity property of the account, independent of its
      secret, so a RID resolved by an earlier run survives a rerun that had no
      SID map to resolve it with (every narrowly scoped rerun is such a run).
    * ``lm_hash`` is likewise kept when the fresh observation has none.
    * ``plaintext_recovered`` is a property of one SECRET, not of the account.
      It stays sticky while the NT hash is unchanged, because a rerun that did
      no offline lookup has not un-recovered anything. When the NT hash differs
      the password rotated, the recovered plaintext belongs to the old secret,
      and the flag resets rather than making a false claim about the new one.
    """
    if not isinstance(previous, dict):
        return current

    merged = dict(current)
    if merged.get("rid") is None and previous.get("rid") is not None:
        merged["rid"] = previous.get("rid")
    if not merged.get("lm_hash") and previous.get("lm_hash"):
        merged["lm_hash"] = previous.get("lm_hash")
    if _normalize_hash(previous.get("nt_hash")) == merged.get("nt_hash"):
        merged["plaintext_recovered"] = bool(
            merged.get("plaintext_recovered") or previous.get("plaintext_recovered")
        )
    return merged


def write_dcsync_dump_file(
    shell: object,
    *,
    domain: str,
    raw_credentials: Iterable[tuple[str, str]],
    plaintext_recovered_users: Iterable[str] = (),
    sid_by_account: dict[str, str] | None = None,
) -> str | None:
    """Merge this DCSync observation into ``domain``'s register and persist it.

    The register accumulates: every account a previous run of this domain
    recorded is carried forward, and the accounts in ``raw_credentials`` are
    folded in on top of it, keyed by sAMAccountName. So a narrowly scoped rerun
    (an attack-path step replicating one principal) updates that principal and
    leaves the rest of a full walk intact, and two narrow runs on different
    principals both survive. Per-account precedence is in :func:`_merge_entry`.

    Resetting the register is deliberate and explicit: delete the file (or start
    from a fresh workspace, which has none). There is no in-band reset, because
    DRSUAPI replication never proves an account is absent — only that it was not
    asked for — so no run can legitimately claim the right to erase another's
    observations.

    Args:
        shell: Runtime shell — used to resolve the workspace path.
        domain: Target domain whose secrets were dumped.
        raw_credentials: Iterable of ``(samaccountname, nt_hash)`` pairs
            as observed by the DCSync stream.
        plaintext_recovered_users: Iterable of samaccountnames whose
            plaintext was recovered (via cracking, GPP, gMSA, etc.).
        sid_by_account: Optional ``{lower(sam): SID}`` map so we can
            persist the RID without having to re-query LDAP.

    Returns:
        The absolute path of the file written, or ``None`` if the
        workspace path cannot be resolved (no-op for ad-hoc shells
        without a workspace).
    """
    workspace_cwd = (
        shell._get_workspace_cwd()  # noqa: SLF001
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", "")
    )
    if not workspace_cwd:
        return None
    domains_dir = getattr(shell, "domains_dir", "domains")
    inventory_dir = domain_subpath(workspace_cwd, domains_dir, domain, "inventory")
    os.makedirs(inventory_dir, exist_ok=True)

    domain_key = _normalize_domain(domain)
    plaintext_set = {str(u or "").strip().lower() for u in plaintext_recovered_users}
    sid_lookup = {k.lower(): v for k, v in (sid_by_account or {}).items()}

    out_path = os.path.join(inventory_dir, DUMP_FILENAME)
    # Start from what previous runs of this domain recorded, so a narrowly
    # scoped rerun adds to the register instead of becoming it.
    merged_by_sam: dict[str, dict] = _load_recorded_entries(out_path, domain_key)

    seen: set[tuple[str, str]] = set()
    for sam_raw, nt_raw in raw_credentials:
        sam = str(sam_raw or "").strip()
        nt = str(nt_raw or "").strip().lower()
        if not sam or not nt:
            continue
        # Composite (sam, nt) dedup — DCSync streams may yield duplicates
        # when retried; keep the first observation OF THIS RUN.
        key = (sam.lower(), nt)
        if key in seen:
            continue
        seen.add(key)
        sid = sid_lookup.get(sam.lower())
        rid = _extract_rid(sid)
        observation = {
            "samaccountname": sam,
            "domain": domain_key,
            "rid": rid,
            "lm_hash": None,
            "nt_hash": nt,
            "is_blank": nt == EMPTY_NT_HASH,
            "is_machine_account": _is_machine_account(sam),
            "plaintext_recovered": sam.lower() in plaintext_set,
        }
        merged_by_sam[sam.lower()] = _merge_entry(
            merged_by_sam.get(sam.lower()), observation
        )

    entries = list(merged_by_sam.values())

    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain_key,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "record_type": "dcsync_dump",
        "count": len(entries),
        "entries": entries,
    }
    write_json_file(out_path, payload)
    return out_path
