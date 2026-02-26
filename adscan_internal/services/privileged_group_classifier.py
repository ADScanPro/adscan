"""Privileged group classification helpers.

This module centralizes the logic used to determine whether a user belongs to
well-known privileged AD groups, using SIDs/RIDs rather than group names.

Rationale:
    Group names can be localized and may differ across environments. SIDs/RIDs
    are stable and language-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


def normalize_sid(value: str) -> str | None:
    """Return a normalized SID string or None when it can't be extracted.

    BloodHound CE sometimes prefixes SIDs with domain strings (e.g.:
    ``HTB.LOCAL-S-1-5-32-548``). Some tools may also embed the SID inside
    additional text. We extract the first ``S-1-`` substring and keep it.
    """
    raw = (value or "").strip()
    if not raw:
        return None

    upper = raw.upper()
    idx = upper.find("S-1-")
    if idx == -1:
        return None

    sid = upper[idx:]
    # Defensive: trim obvious trailing punctuation.
    sid = sid.strip().strip("',\"")
    if not sid.startswith("S-1-"):
        return None
    return sid


def sid_rid(value: str) -> int | None:
    """Return RID from a SID string, or None when it can't be parsed."""
    sid = normalize_sid(value)
    if not sid:
        return None
    try:
        return int(sid.rsplit("-", 1)[-1])
    except Exception:
        return None


@dataclass(frozen=True)
class PrivilegedGroupMembership:
    """Structured privileged membership flags for a principal."""

    domain_admin: bool = False
    administrators: bool = False
    backup_operators: bool = False
    account_operators: bool = False

    def as_dict(self) -> dict[str, Any]:
        """Return a dict compatible with existing `check_privileged_groups` callers."""
        return {
            "domain_admin": bool(self.domain_admin),
            "Administrators": bool(self.administrators),
            "backup_operators": bool(self.backup_operators),
            "account_operators": bool(self.account_operators),
        }


def classify_privileged_membership_from_group_sids(
    group_sids: Iterable[str],
) -> PrivilegedGroupMembership:
    """Classify privileged group membership based on group SIDs.

    Supported roles align with the current `check_privileged_groups` UX/actions:
        - Domain Admins (domain RID 512)
        - BUILTIN\\Administrators (RID 544)
        - BUILTIN\\Backup Operators (RID 551)
        - BUILTIN\\Account Operators (RID 548)
    """
    domain_admin = False
    administrators = False
    backup_operators = False
    account_operators = False

    for raw in group_sids:
        sid = normalize_sid(str(raw))
        if not sid:
            continue

        rid = sid_rid(sid)
        if rid is None:
            continue

        # Domain-specific: Domain Admins.
        if rid == 512:
            domain_admin = True

        # Built-in: match by RID and BUILTIN SID prefix.
        if sid.startswith("S-1-5-32-"):
            if rid == 544:
                administrators = True
            elif rid == 551:
                backup_operators = True
            elif rid == 548:
                account_operators = True

        if domain_admin and administrators and backup_operators and account_operators:
            break

    return PrivilegedGroupMembership(
        domain_admin=domain_admin,
        administrators=administrators,
        backup_operators=backup_operators,
        account_operators=account_operators,
    )
