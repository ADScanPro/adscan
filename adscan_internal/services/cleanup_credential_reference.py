"""The ``cleanup_credential`` section of a scan configuration: a REFERENCE only.

The client's cleanup-only account is named in the scan configuration together
with the ``ADSCAN_*`` environment variable that holds its secret. The secret
itself never appears in the configuration, because that file is written to the
run workspace and would outlive the run in clear. Parsing lives here, apart from
:mod:`cleanup_credential_store`, so the configuration loader never imports the
module that holds secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

__all__ = [
    "CLEANUP_SECRET_ENV_DEFAULT",
    "CleanupCredentialError",
    "CleanupCredentialReference",
    "parse_cleanup_reference",
]

#: Environment variable the secret is read from when the reference names none.
CLEANUP_SECRET_ENV_DEFAULT = "ADSCAN_CLEANUP_SECRET"

_ALLOWED_KEYS = frozenset({"username", "domain", "secret_env"})
_SECRET_KEYS = frozenset({"password", "secret", "hash", "nt_hash"})


class CleanupCredentialError(ValueError):
    """The cleanup-credential reference is malformed; the message says how."""


@dataclass(frozen=True)
class CleanupCredentialReference:
    """What a scan configuration may say about the cleanup account.

    Attributes:
        username: The cleanup principal (sAMAccountName or UPN).
        domain: The domain it authenticates to; empty means every domain the
            run touches (one account for a single-domain engagement).
        secret_env: The ``ADSCAN_*`` environment variable holding the secret.
    """

    username: str
    domain: str = ""
    secret_env: str = CLEANUP_SECRET_ENV_DEFAULT


def parse_cleanup_reference(raw: Any) -> Optional[CleanupCredentialReference]:
    """Validate the ``cleanup_credential`` section.

    Args:
        raw: ``None`` or a mapping with ``username`` and optional ``domain`` and
            ``secret_env``.

    Returns:
        The reference, or ``None`` when the section is absent or empty.

    Raises:
        CleanupCredentialError: unknown keys, a missing username, an inline
            secret, or an environment name outside the ``ADSCAN_`` prefix.
    """
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise CleanupCredentialError(
            "'cleanup_credential' must be a mapping with 'username' and optional "
            "'domain' and 'secret_env'."
        )
    if not raw:
        return None
    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        if _SECRET_KEYS & set(unknown):
            raise CleanupCredentialError(
                "'cleanup_credential' must not carry the secret itself: put it in an "
                f"environment variable (default {CLEANUP_SECRET_ENV_DEFAULT}) and name "
                "that variable in 'secret_env'."
            )
        raise CleanupCredentialError(
            f"'cleanup_credential' has unknown key(s) {unknown}; allowed: "
            f"{sorted(_ALLOWED_KEYS)}."
        )
    username = raw.get("username")
    if not isinstance(username, str) or not username.strip():
        raise CleanupCredentialError("'cleanup_credential.username' must be a non-empty string.")
    domain = raw.get("domain") or ""
    if not isinstance(domain, str):
        raise CleanupCredentialError("'cleanup_credential.domain' must be a string.")
    secret_env = raw.get("secret_env") or CLEANUP_SECRET_ENV_DEFAULT
    if not isinstance(secret_env, str) or not secret_env.strip().startswith("ADSCAN_"):
        raise CleanupCredentialError(
            "'cleanup_credential.secret_env' must name an ADSCAN_* environment "
            "variable (the launcher forwards only that prefix into the scan)."
        )
    return CleanupCredentialReference(
        username=username.strip(), domain=domain.strip(), secret_env=secret_env.strip()
    )
