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

