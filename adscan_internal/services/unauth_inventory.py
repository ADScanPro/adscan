"""Canonical unauth user inventory — single source of truth.

The unauthenticated reconnaissance phase pulls user records from two sources
that overlap but neither dominates:

* **LDAP anonymous bind** — returns `samaccountname`, `distinguishedName`,
  `description`, `userAccountControl` (often withheld on hardened DCs),
  `lastLogonTimestamp`. Misses users hidden by ACLs.
* **SMB null session → SAMR** — returns `username`, `RID`, `description`,
  `fullName`, `comment`. Catches users LDAP withholds (e.g. Forest exposes
  `svc-alfresco` via SAMR but not via anon LDAP).

Historically each probe wrote its own JSON (``ldap_anonymous_active_users.json``,
``samr_users.json``, ``samr_descriptions.json``) and every downstream consumer
(AS-REP roasting, password spraying, attack-graph feed, report renderer) had
to re-merge them. That made every consumer carry merge logic and made
provenance ("which probe found this user?") impossible to recover.

This module is the single point that:

1. Merges both sources into :class:`UnauthUser` records keyed by
   case-insensitive ``samaccountname``.
2. Tracks ``sources`` so the report can cite "discovered via SAMR + LDAP".
3. Picks the richest field across sources (longest description, RID from
   SAMR, DN from LDAP, UAC if any side returned it).
4. Writes a canonical ``domains/<dom>/users.json`` plus a
   ``domains/<dom>/users.txt`` derived from it for tool consumption
   (``run_asreproast`` and friends read the .txt).

Consumers should read ``users.json`` — the per-probe artefacts are gone.
GPP cpassword leaks remain in their own store (``gpp_leaks.json``); they
are credentials, not users.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable
from adscan_core.rich_output import print_exception


@dataclass
class UnauthUser:
    """Unified user record merging LDAP anon + SAMR data.

    ``samaccountname`` carries the canonical case (preserved from the source
    that returned it first). ``sources`` is the audit trail — it records
    every probe that confirmed this account, which the report cites.
    """

    samaccountname: str
    sources: list[str] = field(default_factory=list)
    rid: int | None = None
    distinguished_name: str = ""
    description: str = ""
    full_name: str = ""
    comment: str = ""
    user_account_control: int = 0
    last_logon_timestamp: str | None = None
    asreproast_eligible: bool = False


def _prefer_longer(a: str, b: str) -> str:
    """Pick the more informative of two string fields.

    Empty/whitespace strings lose. Among non-empty values we prefer the
    longer one — descriptions like ``"Built-in account for administering…"``
    win over the empty string SAMR returns when ``description`` is unset
    on the account but ``comment`` is not.
    """
    a = (a or "").strip()
    b = (b or "").strip()
    if not a:
        return b
    if not b:
        return a
    return a if len(a) >= len(b) else b


def merge_unauth_users(
    ldap_users: Iterable[Any],
    samr_users: Iterable[Any],
) -> list[UnauthUser]:
    """Merge LDAP + SAMR user records into the canonical inventory.

    Keys are case-insensitive ``samaccountname``. Order is alphabetical by
    sam (case-insensitive) so the artefact diff-friendly across runs.
    """
    by_key: dict[str, UnauthUser] = {}

    for u in ldap_users:
        sam = (getattr(u, "samaccountname", "") or "").strip()
        if not sam:
            continue
        key = sam.lower()
        rec = by_key.setdefault(key, UnauthUser(samaccountname=sam))
        if "ldap" not in rec.sources:
            rec.sources.append("ldap")
        rec.distinguished_name = rec.distinguished_name or (
            getattr(u, "distinguished_name", "") or ""
        )
        rec.description = _prefer_longer(rec.description, getattr(u, "description", ""))
        uac = getattr(u, "user_account_control", 0) or 0
        if uac and not rec.user_account_control:
            rec.user_account_control = uac
        last_logon = getattr(u, "last_logon_timestamp", None)
        if last_logon and not rec.last_logon_timestamp:
            rec.last_logon_timestamp = str(last_logon)
        if getattr(u, "asreproast_eligible", False):
            rec.asreproast_eligible = True

    for u in samr_users:
        sam = (getattr(u, "username", "") or "").strip()
        if not sam:
            continue
        key = sam.lower()
        rec = by_key.setdefault(key, UnauthUser(samaccountname=sam))
        if "samr" not in rec.sources:
            rec.sources.append("samr")
        rid = getattr(u, "rid", None)
        if rid is not None and rec.rid is None:
            rec.rid = int(rid)
        rec.description = _prefer_longer(rec.description, getattr(u, "description", ""))
        rec.full_name = _prefer_longer(rec.full_name, getattr(u, "full_name", ""))
        rec.comment = _prefer_longer(rec.comment, getattr(u, "comment", ""))

    return sorted(by_key.values(), key=lambda r: r.samaccountname.lower())


@dataclass
class DescriptionCredential:
    """A credential pattern found inside a user's description / fullName / comment.

    Sourced from CredSweeper running in-memory over the merged user inventory.
    The historical AD anti-pattern of writing initial passwords into the
    description field (so help-desk can read them back to users) is still
    common — hardened DCs that withhold ``userAccountControl`` from anonymous
    binds happily return descriptions, so this attack often works where
    AS-REP roasting fails.

    ``rule_name`` is the CredSweeper rule that fired (e.g. ``Password``,
    ``Generic Secret``); ``ml_probability`` is the model score (None when
    the rule fired without ML scoring).
    """

    samaccountname: str
    field: str  # "description" | "full_name" | "comment"
    raw_value: str
    context_line: str
    rule_name: str
    ml_probability: float | None = None


def scan_description_credentials(
    users: list[UnauthUser],
) -> list[DescriptionCredential]:
    """Run CredSweeper in-memory over the description / fullName / comment
    fields of the merged inventory.

    Returns an empty list on any CredSweeper failure — credential leaks in
    descriptions are a bonus, not a hard requirement of the enrichment phase,
    so we never let a credsweeper crash break the unauth flow.
    """
    from adscan_internal.services.credsweeper_library_service import (
        CredSweeperLibraryService,
        InMemoryCredSweeperTarget,
    )
    from adscan_internal.services.credsweeper_service import (
        CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION,
    )
    from adscan_core.rich_output import print_warning_debug

    targets: list[InMemoryCredSweeperTarget] = []
    path_index: dict[str, tuple[str, str]] = {}
    for u in users:
        for field_name in ("description", "full_name", "comment"):
            value = (getattr(u, field_name, "") or "").strip()
            if not value:
                continue
            key = f"unauth/{u.samaccountname}/{field_name}"
            targets.append(
                InMemoryCredSweeperTarget(
                    content=value.encode("utf-8", errors="replace"),
                    file_path=key,
                    file_type=".txt",
                    info=f"{u.samaccountname}/{field_name}",
                )
            )
            path_index[key] = (u.samaccountname, field_name)

    if not targets:
        return []

    try:
        # doc=True: activates target=[doc] rules (DOC_CREDENTIALS, DOC_GET,
        # DOC Password To/Inline, etc.) alongside target=[code,doc] custom rules.
        # ByteContentProvider is now used for plain-text even when doc=True
        # (fixed in credsweeper_library_service._build_provider_for_target) so
        # DataContentProvider's silent-skip-on-plain-text issue is gone.
        raw = CredSweeperLibraryService().analyze_targets_with_options(
            targets,
            rules_profile=CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION,
            include_custom_rules=True,
            ml_threshold="0.0",
            no_filters=True,
            doc=True,
        )
    except Exception as exc:  # noqa: BLE001
        from adscan_core import telemetry

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning_debug(
            f"Description credsweeper scan skipped: {type(exc).__name__}: {exc}"
        )
        return []

    findings: list[DescriptionCredential] = []
    for rule_name, entries in raw.items():
        for value, ml_probability, context_line, _line_num, file_path in entries:
            if file_path not in path_index:
                continue
            sam, field_name = path_index[file_path]
            findings.append(
                DescriptionCredential(
                    samaccountname=sam,
                    field=field_name,
                    raw_value=value,
                    context_line=context_line,
                    rule_name=rule_name,
                    ml_probability=ml_probability,
                )
            )
    return findings


def merge_rid_cycling_users(
    existing: list[UnauthUser],
    rid_entries: "Iterable[Any]",
) -> list[UnauthUser]:
    """Merge RID-cycling results (LSARPCRidEntry) into the canonical inventory.

    Only SID_TYPE_USER (1) accounts are included — machine accounts ending
    in ``$`` are filtered out so they don't pollute the spray/roast wordlist.
    RID cycling becomes a third discovery source tracked as ``"rid_cycling"``
    in the ``sources`` field alongside ``"ldap"`` and ``"samr"``.
    """
    SID_TYPE_USER = 1
    by_key: dict[str, UnauthUser] = {u.samaccountname.lower(): u for u in existing}

    for entry in rid_entries:
        sid_type = getattr(entry, "sid_type", None)
        if sid_type != SID_TYPE_USER:
            continue
        name = str(getattr(entry, "name", "") or "").strip()
        if not name or name.endswith("$"):
            continue
        key = name.lower()
        rec = by_key.setdefault(key, UnauthUser(samaccountname=name))
        if "rid_cycling" not in rec.sources:
            rec.sources.append("rid_cycling")
        rid = getattr(entry, "rid", None)
        if rid is not None and rec.rid is None:
            try:
                rec.rid = int(rid)
            except (TypeError, ValueError):
                pass

    return sorted(by_key.values(), key=lambda r: r.samaccountname.lower())


def persist_unauth_users(
    users: list[UnauthUser],
    *,
    domain_root: str,
) -> tuple[str, str]:
    """Write ``users.json`` (canonical) and ``users.txt`` (tool-friendly).

    Returns ``(json_path, txt_path)``. Callers are expected to ensure
    ``domain_root`` exists. Writes are best-effort — exceptions propagate so
    the caller can capture them via telemetry.
    """
    json_path = os.path.join(domain_root, "users.json")
    txt_path = os.path.join(domain_root, "users.txt")

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump([asdict(u) for u in users], fh, indent=2)

    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(u.samaccountname for u in users) + ("\n" if users else ""))

    return json_path, txt_path
