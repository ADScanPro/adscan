"""Credential storage service for domain and local credentials.

This module centralizes updates to the in-memory ``domains_data`` mapping that
is currently maintained by the CLI shell in ``adscan.py``. The goal is to
express these updates in a reusable, testable service that can be consumed
both by the CLI and by future frontends (e.g. a web backend).

The store focuses on:

* Ensuring per-domain structures exist in ``domains_data``.
* Adding/updating domain credentials.
* Adding/updating local credentials (host/service-scoped).
* Tracking Kerberos ticket artefacts for domain users.

It deliberately does **not** perform any verification or user interaction;
that responsibility remains in the CLI layer and the dedicated verification
services (``CredentialService`` and ``KerberosTicketService``).
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, MutableMapping, Optional

from adscan_internal.services.base_service import BaseService
from adscan_internal.models.domain import Domain


@dataclass
class DomainCredentialUpdateResult:
    """Result of a domain credential update operation.

    Attributes:
        domain: Domain key used in ``domains_data``.
        username: Username whose credentials were updated.
        is_hash: Whether the stored credential is a hash.
        credential_changed: True if the stored value was changed or added.
    """

    domain: str
    username: str
    is_hash: bool
    credential_changed: bool


@dataclass
class LocalCredentialUpdateResult:
    """Result of a local credential update operation.

    Attributes:
        domain: Domain key used in ``domains_data``.
        host: Target host key.
        service: Service key (e.g. ``\"smb\"``).
        username: Username whose local credential was updated.
        is_hash: Whether the stored credential is a hash.
        credential_changed: True if the stored value was changed or added.
    """

    domain: str
    host: str
    service: str
    username: str
    is_hash: bool
    credential_changed: bool


class CredentialStoreService(BaseService):
    """Service responsible for mutating the ``domains_data`` structure.

    The CLI keeps an in-memory ``CaseInsensitiveDict`` called ``domains_data``
    that aggregates all state for a scan. Historically this structure was
    manipulated directly from many methods in ``adscan.py``; this service
    provides a narrow, well-defined surface for credential-related updates.
    """

    # ------------------------------------------------------------------ #
    # Domain model helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def get_domain_from_mapping(
        domains_data: MutableMapping[str, Any],
        domain: str,
    ) -> Domain:
        """Create a :class:`Domain` model from a ``domains_data`` entry.

        This helper allows higher layers to work with a strongly-typed
        :class:`Domain` object instead of raw dictionaries when convenient.
        """

        raw = domains_data.get(domain, {}) or {}
        return Domain.from_dict(name=domain, data=raw)  # type: ignore[arg-type]

    @staticmethod
    def persist_domain_to_mapping(
        domains_data: MutableMapping[str, Any],
        domain: str,
        domain_obj: Domain,
    ) -> None:
        """Persist a :class:`Domain` model back into the ``domains_data`` mapping."""

        domains_data[domain] = domain_obj.to_dict()

    # ------------------------------------------------------------------ #
    # Domain-level helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def ensure_domain_entry(
        domains_data: MutableMapping[str, Any],
        domain: str,
    ) -> MutableMapping[str, Any]:
        """Ensure that ``domains_data[domain]`` exists and return it."""

        if domain not in domains_data:
            domains_data[domain] = {}
        return domains_data[domain]

    # ------------------------------------------------------------------ #
    # Domain authentication helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def resolve_auth_credentials(
        domains_data: MutableMapping[str, Any],
        *,
        target_domain: str,
        primary_domain: Optional[str] = None,
    ) -> Optional[tuple[str, str, str]]:
        """Resolve the best credentials to use for a target domain.

        The resolution order is:

        1. Credentials configured directly on the target domain entry:
           ``domains_data[target_domain][\"username\"/\"password\"]``.
        2. Credentials configured on the primary/active domain
           (typically ``shell.domain``) when provided.

        Args:
            domains_data: The shared domains_data mapping.
            target_domain: Domain we want to authenticate *to*.
            primary_domain: Optional primary domain whose credentials can be
                used as a fallback (for trusted domains / multi-domain scans).

        Returns:
            A tuple ``(username, password, auth_domain)`` where ``auth_domain``
            is the domain that owns the credentials (either ``target_domain``
            or ``primary_domain``). Returns ``None`` when no suitable
            credentials are found.
        """

        # Prefer credentials attached to the target domain itself
        domain_data = domains_data.get(target_domain, {}) or {}
        username = domain_data.get("username")
        password = domain_data.get("password")
        if username and password:
            return str(username), str(password), target_domain

        # Fallback to the primary/active domain when available
        if primary_domain:
            primary_data = domains_data.get(primary_domain, {}) or {}
            primary_username = primary_data.get("username")
            primary_password = primary_data.get("password")
            if primary_username and primary_password:
                return str(primary_username), str(primary_password), primary_domain

        return None

    # ------------------------------------------------------------------ #
    # Domain credentials
    # ------------------------------------------------------------------ #

    @staticmethod
    def _looks_like_ntlm_hash(value: object) -> bool:
        """Return True if value resembles an NTLM hash string.

        Supports:
        - NT hash: ``32`` hex characters
        - LM:NT format: ``32:32`` hex characters
        """

        if not isinstance(value, str):
            return False
        candidate = value.strip()
        if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
            return True
        if re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", candidate):
            return True
        return False

    def update_domain_credential(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
        credential: str,
        is_hash: bool,
    ) -> DomainCredentialUpdateResult:
        """Add or update a domain credential in ``domains_data``.

        The method mirrors the non-interactive semantics of the legacy CLI
        credential handling:

        * Ensures the ``\"credentials\"`` dictionary exists for the domain.
        * Applies deduplication rules.
        * Prefers plaintext over hashes:
          - Do **not** replace a stored password with a hash.
          - Do replace a stored hash with a password.
        * Stores the final credential string without performing any checks.
        """

        domain_data = self.ensure_domain_entry(domains_data, domain)

        if "credentials" not in domain_data:
            domain_data["credentials"] = {}

        current_cred = domain_data["credentials"].get(username)
        current_is_hash = self._looks_like_ntlm_hash(current_cred)
        credential_changed = False
        stored_is_hash = is_hash

        if current_cred is None:
            credential_changed = True
        else:
            # Prefer plaintext over hashes: never overwrite a password with a hash.
            if (not current_is_hash) and is_hash:
                credential_changed = False
                stored_is_hash = False
            # If we already have the same plaintext, treat as no-op.
            elif (not is_hash) and current_cred == credential:
                credential_changed = False
                stored_is_hash = False
            else:
                credential_changed = current_cred != credential
                stored_is_hash = is_hash if credential_changed else current_is_hash

        if credential_changed:
            domain_data["credentials"][username] = credential

        return DomainCredentialUpdateResult(
            domain=domain,
            username=username,
            is_hash=stored_is_hash,
            credential_changed=credential_changed,
        )

    def delete_domain_credential(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
    ) -> bool:
        """Delete a stored domain credential if present.

        Returns:
            True if a credential was removed, False otherwise.
        """

        domain_data = domains_data.get(domain, {})
        creds = domain_data.get("credentials", {})
        if username in creds:
            del creds[username]
            return True
        return False

    # ------------------------------------------------------------------ #
    # Local credentials
    # ------------------------------------------------------------------ #

    def update_local_credential(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        host: str,
        service: str,
        username: str,
        credential: str,
        is_hash: bool,
    ) -> LocalCredentialUpdateResult:
        """Add or update a local (host/service) credential.

        The storage layout mirrors the historical one in ``domains_data``:

        .. code-block:: python

            domains_data[domain][\"local_credentials\"][host][service][username] = cred
        """

        domain_data = self.ensure_domain_entry(domains_data, domain)

        local_creds = domain_data.setdefault("local_credentials", {})
        host_creds = local_creds.setdefault(host, {})
        service_creds = host_creds.setdefault(service, {})

        current_cred = service_creds.get(username)
        credential_changed = current_cred != credential

        service_creds[username] = credential

        return LocalCredentialUpdateResult(
            domain=domain,
            host=host,
            service=service,
            username=username,
            is_hash=is_hash,
            credential_changed=credential_changed,
        )

    # ------------------------------------------------------------------ #
    # Kerberos tickets
    # ------------------------------------------------------------------ #

    def store_kerberos_ticket(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
        ticket_path: str,
    ) -> None:
        """Register a Kerberos ticket path for a domain user.

        This is the service-layer equivalent of the direct updates to the
        ``\"kerberos_tickets\"`` dictionary that used to live in ``adscan.py``.
        """

        domain_data = self.ensure_domain_entry(domains_data, domain)
        tickets = domain_data.setdefault("kerberos_tickets", {})
        tickets[username] = ticket_path

    def get_kerberos_ticket(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
    ) -> Optional[str]:
        """Return a stored Kerberos ticket path for ``username`` if present."""

        domain_data = domains_data.get(domain, {})
        tickets = domain_data.get("kerberos_tickets", {})
        return tickets.get(username)

    def delete_kerberos_ticket(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
    ) -> bool:
        """Remove a stored Kerberos ticket path for ``username`` if present.

        Returns:
            True if an entry was removed, False otherwise.
        """
        domain_data = domains_data.get(domain, {})
        tickets = domain_data.get("kerberos_tickets", {})
        if not isinstance(tickets, dict):
            return False
        if username not in tickets:
            return False
        tickets.pop(username, None)
        return True

__all__ = [
    "CredentialStoreService",
    "DomainCredentialUpdateResult",
    "LocalCredentialUpdateResult",
]
