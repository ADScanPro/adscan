"""Minimal-sufficient credential resolver for environment-change rollback.

When a cleanup service reverts a change, it should bind with the LEAST-privileged
stored credential able to do the job — the ORIGINAL executor principal that made
the change already had exactly the right over the object, so it is minimal by
construction. Escalation to a Domain-Admin-looking credential is LAZY: it only
happens after a real ACCESS_DENIED, never pre-emptively. This keeps the wire
footprint minimal (no DA bind when a lesser principal suffices) and records WHICH
principal performed each revert into the ledger.

This module centralizes the resolver that previously lived inline in
``acl_change_cleanup_service`` (``_resolve_cleanup_credential`` /
``_resolve_fallback_admin_credential``) so every cleanup service shares one
implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal.principal_utils import normalize_machine_account
from adscan_internal.rich_output import mark_sensitive, print_info_debug


@dataclass
class CleanupCredential:
    """A resolved rollback credential plus escalation metadata.

    Attributes:
        username: The principal to bind as for the revert (may be empty when no
            usable credential was found).
        secret: The principal's password or NT hash (empty when none found).
        principal_label: A short, render-ready description of which principal
            performed (or will perform) the revert — recorded into the ledger's
            ``min_credential_principal`` field. Masked at render time.
        can_escalate_to_da: Whether a privileged-looking fallback credential is
            available to retry on ACCESS_DENIED. The DA credential itself is
            resolved lazily via :func:`resolve_da_escalation_credential`.
        is_escalated: True once this credential is the escalated DA fallback.
    """

    username: str = ""
    secret: str = ""
    principal_label: str = ""
    can_escalate_to_da: bool = False
    is_escalated: bool = False

    @property
    def usable(self) -> bool:
        """Whether the credential has both a username and a secret."""
        return bool(self.username and self.secret)


def _normalize_credential_username(username: str) -> str:
    """Normalize usernames for stored-credential lookup (matches acl service)."""
    value = str(username or "").strip()
    if "\\" in value:
        value = value.split("\\", 1)[1]
    if "@" in value:
        value = value.split("@", 1)[0]
    if value.endswith("$"):
        return normalize_machine_account(value).lower()
    return value.lower()


def _domain_creds(shell: Any, domain: str) -> dict[str, Any]:
    """Return the stored credential dict for a domain (empty when absent)."""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return {}
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return {}
    creds = domain_data.get("credentials")
    return creds if isinstance(creds, dict) else {}


def _lookup_domain_credential(shell: Any, domain: str, username: str) -> str:
    """Resolve one stored credential by username from shell.domains_data."""
    if not domain or not username:
        return ""
    creds = _domain_creds(shell, domain)
    wanted = _normalize_credential_username(username)
    for stored_user, stored_secret in creds.items():
        if _normalize_credential_username(str(stored_user)) == wanted:
            return str(stored_secret or "").strip()
    return ""


def resolve_da_escalation_credential(shell: Any, domain: str) -> tuple[str, str] | None:
    """Return a conservative stored admin-looking credential for lazy escalation.

    Only used AFTER a real ACCESS_DENIED on the minimal-principal attempt. Returns
    ``(username, secret)`` or ``None`` when no privileged-looking credential is
    stored for the domain.
    """
    creds = _domain_creds(shell, domain)
    if not creds:
        return None
    priority_names = ("administrator", "admin", "domain.admin", "da")
    for wanted in priority_names:
        for stored_user, stored_secret in creds.items():
            if _normalize_credential_username(str(stored_user)) == wanted:
                secret = str(stored_secret or "").strip()
                if secret:
                    return str(stored_user), secret
    return None


def resolve_minimal_revert_credential(
    shell: Any,
    *,
    action: dict[str, Any],
    domain: str,
    target_domain: str,
) -> CleanupCredential:
    """Resolve the LEAST-privileged stored credential able to revert ``action``.

    Order (first usable wins):
      1. The ORIGINAL executor principal that made the change. If its password is
         carried in the action, use it directly; otherwise resolve its secret
         from the credential store. Minimal by construction.
      2. The stored credential whose username matches the executor (cross-domain
         lookup against both the change domain and the target domain).
      3. A privileged-looking fallback — surfaced via ``can_escalate_to_da`` but
         NOT used unless the minimal attempt returns ACCESS_DENIED.

    Args:
        shell: The pentest shell carrying ``domains_data``.
        action: The cleanup action dict (carries ``exec_username`` /
            ``exec_password`` when known).
        domain: The change domain.
        target_domain: The target object's domain (may differ across trusts).

    Returns:
        A :class:`CleanupCredential`. ``usable`` is False when no minimal
        credential was found — the caller then decides whether to escalate (if
        ``can_escalate_to_da``) or mark the change manual.
    """
    exec_username = str(action.get("exec_username") or "").strip()
    exec_password = str(action.get("exec_password") or "").strip()

    can_escalate = (
        resolve_da_escalation_credential(shell, target_domain or domain) is not None
    )

    # 1. Original executor with its secret carried inline.
    if exec_username and exec_password:
        return CleanupCredential(
            username=exec_username,
            secret=exec_password,
            principal_label="original executor",
            can_escalate_to_da=can_escalate,
        )

    # 2. Original executor, secret resolved from the credential store.
    if exec_username:
        for lookup_domain in (domain, target_domain):
            resolved = _lookup_domain_credential(shell, lookup_domain, exec_username)
            if resolved:
                print_info_debug(
                    "cleanup-cred rollback credential resolved from stored original "
                    f"executor: user={mark_sensitive(exec_username, 'user')} "
                    f"domain={mark_sensitive(lookup_domain, 'domain')}"
                )
                return CleanupCredential(
                    username=exec_username,
                    secret=resolved,
                    principal_label="original executor",
                    can_escalate_to_da=can_escalate,
                )

    # 3. No minimal principal available — signal escalate (lazy).
    return CleanupCredential(
        username=exec_username,
        secret="",
        principal_label="",
        can_escalate_to_da=can_escalate,
    )


def build_da_escalated_credential(shell: Any, domain: str) -> CleanupCredential | None:
    """Build the escalated DA credential (called ONLY after ACCESS_DENIED)."""
    fallback = resolve_da_escalation_credential(shell, domain)
    if not fallback:
        return None
    fallback_user, fallback_secret = fallback
    print_info_debug(
        "cleanup-cred escalating to stored privileged credential after ACCESS_DENIED: "
        f"user={mark_sensitive(fallback_user, 'user')} "
        f"domain={mark_sensitive(domain, 'domain')}"
    )
    return CleanupCredential(
        username=fallback_user,
        secret=fallback_secret,
        principal_label="DA (escalated after ACCESS_DENIED)",
        can_escalate_to_da=False,
        is_escalated=True,
    )


def looks_like_access_denied(error: str | None) -> bool:
    """Heuristic: does this error string indicate an authorization failure?

    Used to decide whether to escalate to a DA credential. ACCESS_DENIED /
    insufficient-rights / WILL_NOT_PERFORM all warrant a lazy DA retry; a
    timeout / connection error does NOT (that is transient, handled separately).
    """
    s = str(error or "").strip().lower()
    if not s:
        return False
    markers = (
        "access_denied",
        "access denied",
        "insufficient",
        "00002098",  # ERROR_DS_INSUFF_ACCESS_RIGHTS
        "will_not_perform",
        "unwilling",
        "00000005",  # STATUS_ACCESS_DENIED
        "ldap_insufficient_access",
        "constraint",
    )
    return any(m in s for m in markers)


__all__ = [
    "CleanupCredential",
    "resolve_minimal_revert_credential",
    "resolve_da_escalation_credential",
    "build_da_escalated_credential",
    "looks_like_access_denied",
]
