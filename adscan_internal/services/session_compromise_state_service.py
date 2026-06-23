"""Session compromise state helpers for telemetry and UX.

This module tracks whether an ADscan session has reached a compromise
milestone that should be reflected in session-level telemetry uploads.

The state is intentionally kept in-memory on the active shell instance:

* ``unknown``: We have not started a scan where compromise can be evaluated.
* ``none``: A scan started, but no compromise milestone has been observed yet.
* ``user``: At least one user was compromised during the session.
* ``domain``: Full domain compromise was achieved during the session.
"""

from __future__ import annotations

from typing import Any


SESSION_COMPROMISE_STATUS_UNKNOWN = "unknown"
SESSION_COMPROMISE_STATUS_NONE = "none"
SESSION_COMPROMISE_STATUS_USER = "user"
SESSION_COMPROMISE_STATUS_DOMAIN = "domain"

SESSION_COMPROMISE_STATUS_VALUES = frozenset(
    {
        SESSION_COMPROMISE_STATUS_UNKNOWN,
        SESSION_COMPROMISE_STATUS_NONE,
        SESSION_COMPROMISE_STATUS_USER,
        SESSION_COMPROMISE_STATUS_DOMAIN,
    }
)

# Credential-provenance origins that identify a SELF-INTRODUCED credential —
# the scan's own STARTING credential (the INPUT to ``adscan ci auth`` /
# ``start_auth``) and a manually entered one (``creds save`` / ``creds add``).
# Neither was compromised DURING the scan, so they are excluded from the
# compromised-credential counters, the live scan panel, telemetry, and PostHog
# while remaining fully owned principals for attack-path discovery. The origin
# is the existing ``credentials_meta[user]["credential_origin"]`` provenance
# field — there is no parallel flag.
NON_COMPROMISE_ORIGINS = frozenset({"authenticated_scan", "user_provided"})


def _ensure_session_compromise_state(shell: Any) -> None:
    """Ensure shell compromise tracking attributes exist with safe defaults."""
    if not hasattr(shell, "_session_compromise_status"):
        setattr(shell, "_session_compromise_status", SESSION_COMPROMISE_STATUS_UNKNOWN)
    if not hasattr(shell, "_session_compromised_users"):
        setattr(shell, "_session_compromised_users", set())


def normalize_session_compromise_status(value: Any) -> str:
    """Return a valid session compromise status label."""
    normalized = str(value or "").strip().lower()
    if normalized in SESSION_COMPROMISE_STATUS_VALUES:
        return normalized
    return SESSION_COMPROMISE_STATUS_UNKNOWN


def mark_session_compromise_evaluable(shell: Any) -> None:
    """Mark a session as compromise-evaluable once a scan starts."""
    _ensure_session_compromise_state(shell)
    current = normalize_session_compromise_status(
        getattr(shell, "_session_compromise_status", None)
    )
    if current == SESSION_COMPROMISE_STATUS_UNKNOWN:
        setattr(shell, "_session_compromise_status", SESSION_COMPROMISE_STATUS_NONE)


def mark_session_user_compromised(shell: Any, username: str | None) -> None:
    """Record that at least one user was compromised during the session."""
    _ensure_session_compromise_state(shell)

    current = normalize_session_compromise_status(
        getattr(shell, "_session_compromise_status", None)
    )
    if current not in {
        SESSION_COMPROMISE_STATUS_USER,
        SESSION_COMPROMISE_STATUS_DOMAIN,
    }:
        setattr(shell, "_session_compromise_status", SESSION_COMPROMISE_STATUS_USER)

    normalized_user = str(username or "").strip().lower()
    if normalized_user:
        compromised_users = getattr(shell, "_session_compromised_users", set())
        if not isinstance(compromised_users, set):
            compromised_users = set()
        compromised_users.add(normalized_user)
        setattr(shell, "_session_compromised_users", compromised_users)


def mark_session_domain_compromised(shell: Any) -> None:
    """Record that full domain compromise was achieved during the session."""
    _ensure_session_compromise_state(shell)
    setattr(shell, "_session_compromise_status", SESSION_COMPROMISE_STATUS_DOMAIN)


def is_self_introduced_credential(shell: Any, domain: str, username: str) -> bool:
    """Return True when ``username``'s credential was self-introduced.

    "Self-introduced" means its recorded provenance origin is in
    :data:`NON_COMPROMISE_ORIGINS` — the scan's own STARTING credential
    (``authenticated_scan``, the INPUT to ``adscan ci auth`` / ``start_auth``)
    or a manually entered one (``user_provided``, via ``creds save`` /
    ``creds add``). Reads the existing
    ``credentials_meta[username]["credential_origin"]`` provenance field.
    Pure read; never raises.
    """
    try:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return False
        domain_data = domains_data.get(domain)
        if not isinstance(domain_data, dict):
            return False
        meta_map = domain_data.get("credentials_meta")
        if not isinstance(meta_map, dict):
            return False
        key = str(username or "").strip().lower()
        meta = meta_map.get(key)
        if not isinstance(meta, dict):
            return False
        origin = str(meta.get("credential_origin") or "").strip().lower()
        return origin in NON_COMPROMISE_ORIGINS
    except Exception:  # noqa: BLE001 - pure read, never breaks callers
        return False


def iter_compromised_credentials(shell: Any, domain: str) -> dict[str, str]:
    """Return the domain ``credentials`` map MINUS self-introduced ones.

    This is the single source of truth for "credentials compromised during
    the scan" — every counter, table, and panel that wants to show
    *compromised* (as opposed to *all stored*) credentials must route
    through here. Credentials whose provenance origin is in
    :data:`NON_COMPROMISE_ORIGINS` (the scan's own starting credential or a
    manually entered one) are excluded so they are never double-counted as a
    win. Pure read; never raises (returns ``{}`` on any error).
    """
    out: dict[str, str] = {}
    try:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return out
        domain_data = domains_data.get(domain)
        if not isinstance(domain_data, dict):
            return out
        creds = domain_data.get("credentials")
        if not isinstance(creds, dict):
            return out
        for user, secret in creds.items():
            if not isinstance(user, str) or not isinstance(secret, str):
                continue
            if is_self_introduced_credential(shell, domain, user):
                continue
            out[user] = secret
        return out
    except Exception:  # noqa: BLE001 - pure read, never breaks callers
        return out


def build_session_compromise_metadata(shell: Any) -> dict[str, Any]:
    """Return telemetry-safe compromise metadata for one shell session."""
    _ensure_session_compromise_state(shell)
    status = normalize_session_compromise_status(
        getattr(shell, "_session_compromise_status", None)
    )
    compromised_users = getattr(shell, "_session_compromised_users", set())
    if not isinstance(compromised_users, set):
        compromised_users = set()

    return {
        "compromise_status": status,
        "user_compromised": status in {
            SESSION_COMPROMISE_STATUS_USER,
            SESSION_COMPROMISE_STATUS_DOMAIN,
        },
        "domain_compromised": status == SESSION_COMPROMISE_STATUS_DOMAIN,
        "compromised_users_count": len(compromised_users),
    }

