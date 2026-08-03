"""One weakness, one client-facing finding — the alias-family SSOT.

Several weaknesses are observed by more than one producer. SMBv1 is seen both
by the collector's audit analyzer (``smb_v1_enabled``) and by the SMB scan
posture path (``smbv1_enabled``); a password typed into an account's
description is seen by the authenticated LDAP credential-field analyzer
(``credential_in_ldap_attribute``), by the LDAP description sweep
(``ldap_user_description_password_leak``) and by the unauthenticated
enrichment sweep (``user_description_credential_leak``). Each of those keys
has a live detector, so none of them can simply be renamed away.

What must not happen is the client seeing the same weakness listed twice, at
two severities, in one report — which is exactly what a scan that ran two of
those detectors produced. It inflates the finding count and the severity
distribution, and an auditor asking "why is this here twice?" has no answer.

**The producers stay; the presentation converges.** This module declares the
families once and collapses a domain's findings list at the boundary where the
artifact is read, so:

* a scan in which only ONE member of a family fired is left **completely
  untouched** — same key, same severity, same prose. The candidate-vs-confirmed
  grading the catalog authors deliberately built (a pattern sweep is graded one
  band below a confirmed credential) is preserved, because there is nothing to
  merge;
* a scan in which two or more members fired yields ONE finding carrying the
  canonical key, the **highest** severity observed, and the **union** of every
  affected object, detail container and evidence entry the producers recorded.

Collapsing at the read boundary (rather than rewriting the key at record time)
is what makes a workspace recorded by an older build converge too: the two keys
are already on disk there, and only a merge can bring them back together.

This module lives under ``adscan_core`` so both tiers and the web ingestion
consume one declaration; it imports nothing beyond the LITE-safe catalog slice.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from adscan_core.reporting.vuln_catalog_meta import VULN_CATALOG_META

#: Key under which the structured affected-asset entities ride in a finding's
#: ``details``. Mirrors ``affected_assets_struct.SERIALIZED_KEY``; duplicated as
#: a literal because that module lives in ``adscan_internal`` and this one must
#: stay importable from LITE and from the web backend.
_AFFECTED_ASSETS_KEY = "_affected_assets_struct"

#: Severity ordering used to pick which member of a family leads the merged
#: record. Anything unrecognised sorts last.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass(frozen=True)
class FindingAliasFamily:
    """A set of finding keys that describe ONE underlying weakness.

    Attributes:
        canonical: The key the merged finding carries. It is the identity every
            downstream consumer keys on — compliance mapping, affected-asset
            rules, CVSS context — so it must be the member whose asset rule and
            catalog entry describe the weakness most completely.
        aliases: The other spellings, each with its own live producer.
        rationale: Why these are one weakness, for the next reader.
    """

    canonical: str
    aliases: tuple[str, ...]
    rationale: str

    @property
    def members(self) -> tuple[str, ...]:
        """Return every key in the family, canonical first."""
        return (self.canonical, *self.aliases)


#: The declared families. Adding a member here is the ONLY supported way to say
#: "these two keys are the same weakness" — the compliance mapping derives its
#: equivalence groups from this tuple, and the collapse below is driven by it.
#:
#: Deliberately NOT declared: ``ntlm_authentication_accepted`` and
#: ``ntlmv1_enabled``. They co-occur, but they are different weaknesses with
#: different fixes — the first is "NTLM is accepted at all" (restrict NTLM by
#: policy), the second is "the NTLMv1 dialect specifically is accepted" (raise
#: LmCompatibilityLevel so LM and NTLMv1 responses are refused). A client can
#: close the second without closing the first.
FINDING_ALIAS_FAMILIES: tuple[FindingAliasFamily, ...] = (
    FindingAliasFamily(
        canonical="credential_in_ldap_attribute",
        aliases=(
            "ldap_user_description_password_leak",
            "user_description_credential_leak",
        ),
        rationale=(
            "A secret stored in a directory account attribute, seen over three "
            "channels: the authenticated credential-field analyzer, the LDAP "
            "description sweep, and the unauthenticated enrichment sweep. Same "
            "attribute, same account, same fix."
        ),
    ),
    FindingAliasFamily(
        canonical="smb_v1_enabled",
        aliases=("smbv1_enabled",),
        rationale=(
            "A host still accepting the SMBv1 dialect, seen by the collector's "
            "audit analyzer and by the SMB scan posture path."
        ),
    ),
    FindingAliasFamily(
        canonical="password_not_req",
        aliases=("password_not_required",),
        rationale=(
            "PASSWD_NOTREQD set on an enabled account, seen by the collector "
            "and by the LDAP account-flags scan."
        ),
    ),
)


def _build_canonical_index() -> dict[str, str]:
    """Return ``{member key: canonical key}`` for every declared family."""
    index: dict[str, str] = {}
    for family in FINDING_ALIAS_FAMILIES:
        for member in family.members:
            index[member] = family.canonical
    return index


_CANONICAL_BY_MEMBER: dict[str, str] = _build_canonical_index()


def canonical_finding_key(key: Any) -> str | None:
    """Return the canonical key for *key*, or ``None`` when it has no family.

    Args:
        key: A finding key as recorded in ``technical_report.json``.

    Returns:
        The family's canonical key when *key* is a declared member (including
        when it already IS the canonical), otherwise ``None``.
    """
    if not isinstance(key, str):
        return None
    return _CANONICAL_BY_MEMBER.get(key.strip())


def _severity_rank(finding: Mapping[str, Any]) -> int:
    """Rank a finding by its recorded severity, falling back to the catalog."""
    severity = str(finding.get("severity") or "").strip().lower()
    if not severity:
        key = str(finding.get("key") or "").strip()
        severity = str((VULN_CATALOG_META.get(key) or {}).get("severity") or "").lower()
    return _SEVERITY_RANK.get(severity, len(_SEVERITY_RANK))


def _entity_identity(entity: Any) -> str:
    """Return a stable identity for one structured affected-asset entity.

    Two producers naming the same object write the same ``type`` and
    ``identifier`` but often a different ``display`` (``"jdoe"`` versus
    ``"jdoe · description"``), so identity is taken from those two fields only.
    Anything unrecognised falls back to its JSON form, which at worst keeps a
    duplicate rather than dropping a real asset.
    """
    if isinstance(entity, Mapping):
        kind = str(entity.get("type") or "").strip().lower()
        identifier = str(entity.get("identifier") or "").strip().lower()
        if identifier:
            return f"{kind}\x00{identifier}"
    return _stable_repr(entity)


def _stable_repr(value: Any) -> str:
    """Return a deterministic string form of *value* for de-duplication."""
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(value)


def _merge_entity_lists(base: list[Any], extra: Iterable[Any]) -> list[Any]:
    """Union two affected-asset lists, keeping the first record per object."""
    seen = {_entity_identity(item) for item in base}
    merged = list(base)
    for item in extra:
        identity = _entity_identity(item)
        if identity in seen:
            continue
        seen.add(identity)
        merged.append(item)
    return merged


def _merge_lists(base: list[Any], extra: Iterable[Any]) -> list[Any]:
    """Concatenate two lists, dropping entries already present in *base*."""
    seen = {_stable_repr(item) for item in base}
    merged = list(base)
    for item in extra:
        marker = _stable_repr(item)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(item)
    return merged


def _merge_details(base: dict[str, Any], extra: Mapping[str, Any]) -> None:
    """Merge one member's ``details`` into the leading member's, in place.

    The leading member wins every scalar conflict, with two exceptions that are
    the whole point of the union: list-valued containers (the per-account record
    lists each detector writes under its own name, and the structured affected
    assets) are combined rather than overwritten, and two numbers for the same
    key take the larger — a count must never shrink because a second producer
    saw fewer objects than the first.
    """
    for key, value in extra.items():
        if key not in base:
            base[key] = value
            continue
        current = base[key]
        if (
            key == _AFFECTED_ASSETS_KEY
            and isinstance(current, list)
            and isinstance(value, list)
        ):
            base[key] = _merge_entity_lists(current, value)
        elif isinstance(current, list) and isinstance(value, list):
            base[key] = _merge_lists(current, value)
        elif isinstance(current, dict) and isinstance(value, Mapping):
            _merge_details(current, value)
        elif (
            isinstance(current, (int, float))
            and isinstance(value, (int, float))
            and not isinstance(current, bool)
            and not isinstance(value, bool)
        ):
            base[key] = max(current, value)
        elif not current and value:
            base[key] = value


def _earliest(*values: Any) -> str | None:
    """Return the smallest non-empty ISO timestamp among *values*."""
    stamps = sorted(str(v) for v in values if isinstance(v, str) and v)
    return stamps[0] if stamps else None


def _latest(*values: Any) -> str | None:
    """Return the largest non-empty ISO timestamp among *values*."""
    stamps = sorted(str(v) for v in values if isinstance(v, str) and v)
    return stamps[-1] if stamps else None


def _merge_family(canonical: str, members: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge two or more findings of one family into a single record.

    The record that leads is the one carrying the highest severity, so the
    merged finding inherits its title, severity, category, CVSS base and
    knowledge prose. Under-reporting a real weakness is the worse error, and
    when a pattern sweep and a confirmed credential both fire on the same
    attribute the confirmed reading is the accurate one.

    Args:
        canonical: The family's canonical key.
        members: Every recorded finding of that family, in document order.

    Returns:
        A new finding dict. The inputs are not mutated.
    """
    ordered = sorted(range(len(members)), key=lambda i: (_severity_rank(members[i]), i))
    lead = members[ordered[0]]

    merged: dict[str, Any] = {
        k: v for k, v in lead.items() if k not in ("details", "evidence")
    }
    merged["key"] = canonical
    details = lead.get("details")
    merged["details"] = dict(details) if isinstance(details, dict) else {}
    evidence = lead.get("evidence")
    merged["evidence"] = list(evidence) if isinstance(evidence, list) else []

    for index in ordered[1:]:
        other = members[index]
        other_details = other.get("details")
        if isinstance(other_details, Mapping):
            _merge_details(merged["details"], other_details)
        other_evidence = other.get("evidence")
        if isinstance(other_evidence, list):
            merged["evidence"] = _merge_lists(merged["evidence"], other_evidence)
        merged["first_seen"] = _earliest(
            merged.get("first_seen"), other.get("first_seen")
        )
        merged["discovered_at"] = _earliest(
            merged.get("discovered_at"), other.get("discovered_at")
        )
        merged["last_seen"] = _latest(merged.get("last_seen"), other.get("last_seen"))
        if other.get("from_attack_graph"):
            merged["from_attack_graph"] = True

    for field in ("first_seen", "discovered_at", "last_seen"):
        if merged.get(field) is None:
            merged.pop(field, None)

    # Audit trail: which producers contributed, in document order. Kept on the
    # record so a reviewer can see the merge happened without re-running a scan.
    merged["alias_keys"] = [
        str(member.get("key") or "").strip()
        for member in members
        if str(member.get("key") or "").strip()
    ]
    return merged


def collapse_finding_aliases(
    findings: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Collapse alias-family duplicates in one domain's findings list.

    A family with a single member present is passed through untouched (the same
    object, not a copy), so the overwhelmingly common case costs nothing and
    changes nothing. Only when two or more members of one family are present is
    a merged record produced, and it takes the position of the first member so
    the list's ordering is stable.

    Args:
        findings: A domain's ``findings`` list from ``technical_report.json``.

    Returns:
        A new list with each family reduced to one entry. Non-dict entries and
        findings outside every family are preserved in place.
    """
    if not isinstance(findings, list):
        return []

    out: list[Any] = []
    slots: dict[str, int] = {}
    groups: dict[str, list[dict[str, Any]]] = {}

    for finding in findings:
        if not isinstance(finding, dict):
            out.append(finding)
            continue
        canonical = canonical_finding_key(finding.get("key"))
        if canonical is None:
            out.append(finding)
            continue
        groups.setdefault(canonical, []).append(finding)
        if canonical not in slots:
            slots[canonical] = len(out)
            out.append(None)

    for canonical, members in groups.items():
        out[slots[canonical]] = (
            members[0] if len(members) == 1 else _merge_family(canonical, members)
        )
    return out


def normalize_technical_report(report: Any) -> bool:
    """Collapse alias duplicates across every domain of a technical report.

    Mutates ``report["domains"][*]["findings"]`` in place so the artifact — the
    contract every consumer reads, including the web ingestion — carries one
    entry per weakness.

    Args:
        report: A parsed ``technical_report.json`` payload. Anything else is
            ignored.

    Returns:
        ``True`` when at least one domain's findings list actually changed, so
        a caller holding the file open can decide whether to persist it.
    """
    if not isinstance(report, dict):
        return False
    domains = report.get("domains")
    if not isinstance(domains, dict):
        return False

    changed = False
    for entry in domains.values():
        if not isinstance(entry, dict):
            continue
        findings = entry.get("findings")
        if not isinstance(findings, list) or not findings:
            continue
        collapsed = collapse_finding_aliases(findings)
        if len(collapsed) != len(findings):
            entry["findings"] = collapsed
            changed = True
    return changed


__all__ = (
    "FINDING_ALIAS_FAMILIES",
    "FindingAliasFamily",
    "canonical_finding_key",
    "collapse_finding_aliases",
    "normalize_technical_report",
)
