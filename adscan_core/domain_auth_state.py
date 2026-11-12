"""Single predicate for "does this domain have an authenticated session?".

``domains_data[domain]["auth"]`` holds the domain's session state. Compromising
a domain (``pwned``) is reached THROUGH an authenticated session, so ``pwned``
is authenticated by definition. A check written as ``auth == "auth"`` or
``auth != "auth"`` silently treats a compromised domain as unauthenticated:
the compromised-domain run printed "requires an authenticated session" and
skipped authenticated branches. Every check on this state goes through here.

Dependency-light: stdlib only.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: States that mean an authenticated session exists on the domain.
AUTHENTICATED_DOMAIN_STATES: frozenset[str] = frozenset({"auth", "pwned"})


def normalize_domain_auth_state(value: Any) -> str:
    """Return the auth state as a stripped, lower-case string ("" when absent)."""
    return str(value or "").strip().lower()


def is_authenticated_state(value: Any) -> bool:
    """True when ``value`` (a raw auth state) means an authenticated session."""
    return normalize_domain_auth_state(value) in AUTHENTICATED_DOMAIN_STATES


def domain_is_authenticated(domains_data: Mapping[str, Any] | None, domain: str) -> bool:
    """True when ``domains_data[domain]`` holds an authenticated (or pwned) session."""
    entry = (domains_data or {}).get(domain)
    if not isinstance(entry, Mapping):
        return False
    return is_authenticated_state(entry.get("auth"))
