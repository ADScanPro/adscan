"""Persisted MachineAccountQuota posture for domain principals."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _normalize_domain_username(username: str) -> str:
    """Normalize a domain username for MAQ posture tracking."""
    token = str(username or "").strip().lower()
    if "\\" in token:
        token = token.split("\\", 1)[1]
    if "@" in token:
        token = token.split("@", 1)[0]
    return token.rstrip("$")


def _domain_posture_bucket(shell: Any, domain: str) -> dict[str, Any]:
    """Return the mutable per-domain MAQ posture bucket."""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        domains_data = {}
        setattr(shell, "domains_data", domains_data)
    domain_bucket = domains_data.setdefault(domain, {})
    if not isinstance(domain_bucket, dict):
        domain_bucket = {}
        domains_data[domain] = domain_bucket
    posture = domain_bucket.setdefault("machine_account_quota_posture", {})
    if not isinstance(posture, dict):
        posture = {}
        domain_bucket["machine_account_quota_posture"] = posture
    exhausted = posture.setdefault("exhausted_users", {})
    if not isinstance(exhausted, dict):
        exhausted = {}
        posture["exhausted_users"] = exhausted
    return posture


def mark_machine_account_quota_exhausted(
    shell: Any,
    *,
    domain: str,
    username: str,
    reason: str,
) -> None:
    """Persist that one user can no longer create machine accounts in this domain."""
    normalized = _normalize_domain_username(username)
    if not normalized:
        return
    posture = _domain_posture_bucket(shell, domain)
    exhausted_users = posture["exhausted_users"]
    exhausted_users[normalized] = {
        "reason": str(reason or "").strip(),
        "source": "addcomputer.py",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


def clear_machine_account_quota_exhausted(
    shell: Any,
    *,
    domain: str,
    username: str,
) -> None:
    """Remove a previously persisted MAQ-exhausted marker after a later success."""
    normalized = _normalize_domain_username(username)
    if not normalized:
        return
    posture = _domain_posture_bucket(shell, domain)
    exhausted_users = posture["exhausted_users"]
    exhausted_users.pop(normalized, None)


def is_machine_account_quota_exhausted(
    shell: Any,
    *,
    domain: str,
    username: str,
) -> bool:
    """Return whether one user is already marked as MAQ-exhausted."""
    normalized = _normalize_domain_username(username)
    if not normalized:
        return False
    posture = _domain_posture_bucket(shell, domain)
    exhausted_users = posture["exhausted_users"]
    return normalized in exhausted_users


def get_machine_account_quota_exhausted_reason(
    shell: Any,
    *,
    domain: str,
    username: str,
) -> str | None:
    """Return the persisted MAQ exhaustion reason for one user when present."""
    normalized = _normalize_domain_username(username)
    if not normalized:
        return None
    posture = _domain_posture_bucket(shell, domain)
    exhausted_users = posture["exhausted_users"]
    entry = exhausted_users.get(normalized)
    if not isinstance(entry, dict):
        return None
    reason = str(entry.get("reason") or "").strip()
    return reason or None


def get_machine_account_quota_exhausted_observed_at(
    shell: Any,
    *,
    domain: str,
    username: str,
) -> str | None:
    """Return when MAQ exhaustion was last observed for one user."""
    normalized = _normalize_domain_username(username)
    if not normalized:
        return None
    posture = _domain_posture_bucket(shell, domain)
    exhausted_users = posture["exhausted_users"]
    entry = exhausted_users.get(normalized)
    if not isinstance(entry, dict):
        return None
    observed_at = str(entry.get("observed_at") or "").strip()
    return observed_at or None


__all__ = [
    "clear_machine_account_quota_exhausted",
    "get_machine_account_quota_exhausted_observed_at",
    "get_machine_account_quota_exhausted_reason",
    "is_machine_account_quota_exhausted",
    "mark_machine_account_quota_exhausted",
]
