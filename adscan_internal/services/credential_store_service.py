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
from enum import Enum
import re
from typing import Any, MutableMapping, Optional

from adscan_internal.services.base_service import BaseService
from adscan_internal.models.domain import Domain, resolve_ci
from adscan_core.rich_output import print_exception
from adscan_core.sensitive import strip_sensitive_markers


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
    #: Secret kind retained in the typed per-kind slot because it lost the
    #: ranking (``"nt_hash"`` / ``"password"``), or ``""`` when nothing lost.
    retained_secret_kind: str = ""
    #: Provenance strength resolved for the secret that ended up stored.
    provenance_strength: str = "unknown"


class DomainCredentialDeleteOutcome(str, Enum):
    """Why a scoped credential delete did or did not remove anything."""

    #: The stored secret was the one named by the caller and it was removed.
    DELETED = "deleted"

    #: A credential exists for the principal, but it is NOT the secret the
    #: caller named. Nothing was removed — this is the outcome that keeps a
    #: rejection of one secret from destroying another.
    KEPT_DIFFERENT_SECRET = "kept_different_secret"

    #: The stored secret IS the one named, and it is material ADscan proved
    #: (replicated, dumped, read from a directory attribute, or validated by an
    #: authenticating act). Nothing was removed.
    KEPT_PROVEN_PROVENANCE = "kept_proven_provenance"

    #: No credential is stored for the principal.
    ABSENT = "absent"


@dataclass(frozen=True)
class DomainCredentialDeleteResult:
    """Outcome of a scoped (compare-and-delete) domain credential removal.

    Attributes:
        domain: Domain key used in ``domains_data``.
        username: Normalized username the delete was scoped to.
        outcome: What happened, as :class:`DomainCredentialDeleteOutcome`.
        stored_secret_kind: ``"password"`` / ``"nt_hash"`` for the secret that
            was found stored, or ``""`` when nothing was stored.
        provenance_strength: Provenance strength resolved for the stored
            secret (``"proven"`` / ``"candidate"`` / ``"unknown"``).
    """

    domain: str
    username: str
    outcome: DomainCredentialDeleteOutcome
    stored_secret_kind: str = ""
    provenance_strength: str = "unknown"

    @property
    def deleted(self) -> bool:
        """True iff a credential was actually removed."""
        return self.outcome is DomainCredentialDeleteOutcome.DELETED


@dataclass(frozen=True)
class CredentialStoreConsistencyReport:
    """Coherence of ``credentials`` against its sibling ``credentials_meta``.

    ``credentials_meta[user]`` exists to describe the secret in
    ``credentials[user]``. A meta record with no credential is an incoherent
    state that can only come from a bug: the store then advertises an owned
    principal whose secret does not exist, while usable key material sits
    beside it unread.

    Attributes:
        domain: Domain the report describes.
        orphaned_meta_users: Principals holding a meta record with no
            credential.
        reconciled_users: Orphans whose credential was restored from material
            the store still held.
        unreconcilable_users: Orphans with no usable material left. Reported
            rather than silently dropped; a secret is never invented.
    """

    domain: str
    orphaned_meta_users: tuple[str, ...] = ()
    reconciled_users: tuple[str, ...] = ()
    unreconcilable_users: tuple[str, ...] = ()

    @property
    def is_coherent(self) -> bool:
        """True when nothing diverges between the two maps."""
        return not self.orphaned_meta_users


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


@dataclass(frozen=True)
class KerberosKeyMaterial:
    """Typed Kerberos key material for one domain principal.

    This intentionally lives outside the legacy ``credentials`` mapping because
    that mapping is consumed as password/NTLM by many authentication paths.
    """

    username: str
    nt_hash: str | None = None
    aes256: str | None = None
    aes128: str | None = None
    source: str = ""
    target_host: str = ""
    rid: str = ""


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
        origin: str | None = None,
        provenance_strength: str | None = None,
    ) -> DomainCredentialUpdateResult:
        """Add or update a domain credential in ``domains_data``.

        The active secret for a principal is one string, because every
        authentication path in the product resolves ``credentials[username]``
        and expects a password or an NT hash there. What changed is HOW that one
        string is chosen, and what happens to the secret that is not chosen.

        **Ranking is by provenance first, format second.** Material ADscan
        proved — replicated, dumped, read out of a directory attribute, or
        validated by an authenticating act — outranks an unproven string
        whatever its format. The old rule ranked format alone ("prefer plaintext
        over hashes"), so a password scraped out of a ``description`` attribute
        displaced a replicated NT hash and the proven material was gone. At
        EQUAL provenance the format rule still applies, because a plaintext is
        then strictly the more usable of the two.

        **The loser is retained, never discarded.** A hash that loses to a
        stored password is kept in the typed ``nt_hash`` slot (pass-the-hash and
        Kerberos RC4 stay available); a password that loses to proven key
        material is kept in the typed ``password`` slot. One slot per secret
        KIND, so the single active-secret string never costs the operator
        material that was recovered.

        Args:
            domains_data: Shared workspace domain mapping.
            domain: Domain key in ``domains_data``.
            username: Principal owning the credential (normalized to lower
                case, matching every lookup in the codebase).
            credential: The secret string.
            is_hash: Whether the caller's secret is an NT/LM:NT hash.
            origin: Optional machine-readable origin slug for THIS secret. When
                given, the provenance strength is derived from it; when omitted
                the comparison falls back to what the store already recorded.
            provenance_strength: Optional explicit override of the derived
                strength, for a caller that knows better than the slug.

        Returns:
            A :class:`DomainCredentialUpdateResult`.
        """
        from adscan_internal.services.credentials.credential_origin import (  # noqa: PLC0415
            CredentialProvenanceStrength,
            classify_origin_provenance_strength,
            rank_provenance_strength,
        )
        from adscan_internal.services.credentials.privilege_role import (  # noqa: PLC0415
            resolve_secret_provenance_strength,
        )

        domain_data = self.ensure_domain_entry(domains_data, domain)

        if "credentials" not in domain_data:
            domain_data["credentials"] = {}

        # Normalize username to lowercase so lookups (which use lower-cased keys
        # throughout the codebase) always find the credential.  Callers that pass
        # upper-cased names (e.g. kerbrute returning "BANKING$") otherwise produce
        # a key mismatch that silently prevents attack-path execution.
        username = username.lower()
        current_cred = domain_data["credentials"].get(username)
        current_is_hash = self._looks_like_ntlm_hash(current_cred)
        credential_changed = False
        stored_is_hash = is_hash
        retained_secret_kind = ""

        meta = self._credential_meta_record(domain_data, username)
        if provenance_strength is not None:
            incoming_strength: Any = provenance_strength
        elif origin:
            incoming_strength = classify_origin_provenance_strength(origin)
        else:
            incoming_strength = CredentialProvenanceStrength.UNKNOWN
        current_strength = (
            resolve_secret_provenance_strength(meta, current_cred)
            if current_cred is not None
            else CredentialProvenanceStrength.UNKNOWN
        )
        incoming_rank = rank_provenance_strength(incoming_strength)
        current_rank = rank_provenance_strength(current_strength)
        stored_strength = incoming_strength

        if current_cred is None:
            credential_changed = True
        elif current_cred == credential:
            # Same string: nothing to rank, nothing to retain.
            credential_changed = False
            stored_is_hash = current_is_hash
            stored_strength = current_strength
        elif incoming_rank > current_rank:
            # Proven material takes the slot from an unproven string whatever
            # the formats are. The displaced secret is retained below.
            credential_changed = True
        elif incoming_rank < current_rank:
            credential_changed = False
            stored_is_hash = current_is_hash
            stored_strength = current_strength
        elif (not current_is_hash) and is_hash:
            # Equal provenance: a stored plaintext is the more usable secret.
            credential_changed = False
            stored_is_hash = False
            stored_strength = current_strength
        else:
            credential_changed = True

        if credential_changed:
            domain_data["credentials"][username] = credential
            if current_cred is not None:
                retained_secret_kind = self._retain_superseded_secret(
                    domain_data,
                    username=username,
                    secret=current_cred,
                    is_hash=current_is_hash,
                )
        elif current_cred is not None and current_cred != credential:
            retained_secret_kind = self._retain_superseded_secret(
                domain_data,
                username=username,
                secret=credential,
                is_hash=is_hash,
            )

        return DomainCredentialUpdateResult(
            domain=domain,
            username=username,
            is_hash=stored_is_hash,
            credential_changed=credential_changed,
            retained_secret_kind=retained_secret_kind,
            provenance_strength=str(
                getattr(stored_strength, "value", stored_strength) or "unknown"
            ),
        )

    # ------------------------------------------------------------------ #
    # Typed per-kind secret slots (``credentials_meta``)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _credential_meta_record(
        domain_data: MutableMapping[str, Any], username: str
    ) -> dict[str, Any]:
        """Return ``credentials_meta[username]`` as a dict (never ``None``)."""
        meta_map = domain_data.get("credentials_meta")
        if not isinstance(meta_map, dict):
            return {}
        record = meta_map.get(str(username or "").strip().lower())
        return record if isinstance(record, dict) else {}

    @classmethod
    def _retain_superseded_secret(
        cls,
        domain_data: MutableMapping[str, Any],
        *,
        username: str,
        secret: Any,
        is_hash: bool,
    ) -> str:
        """Keep a secret that lost the active slot, in its typed slot.

        One slot per secret KIND inside ``credentials_meta[username]``: the
        existing ``nt_hash`` field, and ``password`` for a cleartext. Both are
        additive, so a workspace written by an older build is unaffected and no
        existing consumer sees a changed shape.

        Returns:
            The kind retained (``"nt_hash"`` / ``"password"``), or ``""`` when
            there was nothing to keep.
        """
        text = str(secret or "").strip()
        if not text:
            return ""
        key = str(username or "").strip().lower()
        if not key:
            return ""
        meta_map = domain_data.get("credentials_meta")
        if not isinstance(meta_map, dict):
            meta_map = {}
            domain_data["credentials_meta"] = meta_map
        record = meta_map.get(key)
        if not isinstance(record, dict):
            record = {}
        kind = "nt_hash" if (is_hash or cls._looks_like_ntlm_hash(text)) else "password"
        record[kind] = text.lower() if kind == "nt_hash" else text
        meta_map[key] = record
        return kind

    def delete_domain_credential(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
        secret: Any,
        allow_proven: bool = False,
    ) -> DomainCredentialDeleteResult:
        """Remove ONE named secret for a principal — compare-and-delete.

        ``secret`` is required and is the whole point: a disposal decision is
        always about a specific secret (the one a verification rejected), never
        about a principal's slot. Deleting by username alone removed whatever
        the slot happened to hold, which is how the rejection of a wrong
        scraped cleartext destroyed a replicated NT hash and its Kerberos keys
        on a live engagement. Nothing is removed unless the stored secret IS
        the one named.

        Material whose provenance is PROVEN is additionally protected: a
        replicated / dumped / directory-read / validated secret is not removed
        here even when it matches. A verification that rejects proven material
        is far more often a stale verification (a rotation, a lockout, a policy
        or a clock) than evidence that the directory's own key material is
        wrong, and the cost is not symmetric: keeping it risks nothing, because
        the lockout argument for disposal is satisfied by not retrying the
        secret, not by erasing it. An operator-directed removal is a different
        act and goes through :meth:`purge_domain_credential_entry`.

        Args:
            domains_data: Shared workspace domain mapping.
            domain: Domain key in ``domains_data``.
            username: Principal the secret belongs to (case-insensitive).
            secret: The exact secret the caller intends to remove.
            allow_proven: Remove the secret even when its provenance is proven.
                Reserved for an explicit operator instruction; the rejection
                path never sets it.

        Returns:
            A :class:`DomainCredentialDeleteResult` naming what happened.
        """
        preview = self.preview_domain_credential_delete(
            domains_data=domains_data,
            domain=domain,
            username=username,
            secret=secret,
            allow_proven=allow_proven,
        )
        if preview.outcome is not DomainCredentialDeleteOutcome.DELETED:
            return preview

        domain_data = self._resolve_domain_data(domains_data, domain)
        creds = domain_data.get("credentials") or {}
        key = self._resolve_credential_key(creds, preview.username)
        if key is None:
            return DomainCredentialDeleteResult(
                domain=domain,
                username=preview.username,
                outcome=DomainCredentialDeleteOutcome.ABSENT,
            )
        del creds[key]
        self._prune_credential_sidecars(domain_data, key)
        return preview

    def preview_domain_credential_delete(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
        secret: Any,
        allow_proven: bool = False,
    ) -> DomainCredentialDeleteResult:
        """Return what :meth:`delete_domain_credential` WOULD do, mutating nothing.

        Exists so a UI can ask the operator only about a removal that can
        actually happen: prompting and then refusing is worse than not
        prompting, and the wording has to name the secret kind that is at
        stake. ``DELETED`` here means "would be removed".
        """
        from adscan_internal.services.credentials.credential_origin import (  # noqa: PLC0415
            CredentialProvenanceStrength,
        )
        from adscan_internal.services.credentials.privilege_role import (  # noqa: PLC0415
            resolve_secret_provenance_strength,
        )

        domain_data = self._resolve_domain_data(domains_data, domain)
        creds = domain_data.get("credentials") or {}
        key = self._resolve_credential_key(creds, username)
        if key is None:
            return DomainCredentialDeleteResult(
                domain=domain,
                username=str(username or "").strip().lower(),
                outcome=DomainCredentialDeleteOutcome.ABSENT,
            )

        stored = creds.get(key)
        stored_kind = "nt_hash" if self._looks_like_ntlm_hash(stored) else "password"
        strength = resolve_secret_provenance_strength(
            self._credential_meta_record(domain_data, key), stored
        )
        strength_value = str(getattr(strength, "value", strength) or "unknown")

        if not self._secrets_match(stored, secret):
            outcome = DomainCredentialDeleteOutcome.KEPT_DIFFERENT_SECRET
        elif (
            not allow_proven
            and strength_value == CredentialProvenanceStrength.PROVEN.value
        ):
            outcome = DomainCredentialDeleteOutcome.KEPT_PROVEN_PROVENANCE
        else:
            outcome = DomainCredentialDeleteOutcome.DELETED

        return DomainCredentialDeleteResult(
            domain=domain,
            username=key,
            outcome=outcome,
            stored_secret_kind=stored_kind,
            provenance_strength=strength_value,
        )

    @staticmethod
    def _resolve_domain_data(
        domains_data: MutableMapping[str, Any], domain: str
    ) -> MutableMapping[str, Any]:
        """Return the per-domain bucket, matched case-insensitively."""
        domain_data = resolve_ci(domains_data, domain)
        if isinstance(domain_data, MutableMapping):
            return domain_data
        fallback = domains_data.get(domain, {}) or {}
        return fallback if isinstance(fallback, MutableMapping) else {}

    def purge_domain_credential_entry(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
        reason: str,
    ) -> bool:
        """Remove a principal's WHOLE credential entry, on operator instruction.

        Deliberately a separate, explicitly-named method rather than the
        default the rejection path can reach: this removes the active secret
        AND the sidecar records that describe it (``credentials_meta``,
        ``kerberos_keys``), which is correct when a human says "delete this
        credential" and destructive in every other case. A failed verification
        must use :meth:`delete_domain_credential`.

        Keeping the sidecars coherent is part of the contract. A meta record
        left behind with no credential advertises an owned principal whose
        secret does not exist, and that divergence is what
        :func:`audit_domain_credential_store` then has to repair.

        Args:
            domains_data: Shared workspace domain mapping.
            domain: Domain key in ``domains_data``.
            username: Principal whose entry is removed (case-insensitive).
            reason: Short machine-readable reason, for the debug trail
                (``"operator_delete"`` / ``"operator_clear"``).

        Returns:
            ``True`` if an entry was removed.
        """
        from adscan_internal.rich_output import (  # noqa: PLC0415
            mark_sensitive,
            print_info_debug,
        )

        domain_data = resolve_ci(domains_data, domain)
        if not isinstance(domain_data, MutableMapping):
            domain_data = domains_data.get(domain, {}) or {}
        creds = domain_data.get("credentials") or {}
        key = self._resolve_credential_key(creds, username)
        if key is None:
            return False
        del creds[key]
        self._prune_credential_sidecars(domain_data, key)
        print_info_debug(
            f"[credential_store] purged credential entry for "
            f"{mark_sensitive(key, 'user')} ({reason})"
        )
        return True

    @staticmethod
    def _resolve_credential_key(creds: Any, username: str) -> str | None:
        """Return the stored key for ``username``, matched case-insensitively."""
        if not isinstance(creds, dict):
            return None
        wanted = str(username or "").strip()
        if not wanted:
            return None
        if wanted in creds:
            return wanted
        folded = wanted.casefold()
        for candidate in creds:
            if str(candidate or "").strip().casefold() == folded:
                return candidate
        return None

    @staticmethod
    def _secrets_match(stored: Any, candidate: Any) -> bool:
        """Compare two secrets for disposal purposes.

        Sensitive markers are invisible zero-width wrappers added for telemetry
        scrubbing, so a marked copy of a secret is the SAME secret and must
        compare equal: otherwise a scoped delete silently becomes a no-op
        depending on which layer handed over the string. Hashes compare
        case-insensitively (hex), passwords byte-exactly.
        """
        left = strip_sensitive_markers(str(stored or ""))
        right = strip_sensitive_markers(str(candidate or ""))
        if not left or not right:
            return left == right
        if CredentialStoreService._looks_like_ntlm_hash(
            left
        ) and CredentialStoreService._looks_like_ntlm_hash(right):
            return left.casefold() == right.casefold()
        return left == right

    @staticmethod
    def _prune_credential_sidecars(
        domain_data: MutableMapping[str, Any], key: str
    ) -> None:
        """Drop the records that only describe a now-removed credential."""
        for bucket_name in ("credentials_meta", "kerberos_keys"):
            bucket = domain_data.get(bucket_name)
            if not isinstance(bucket, dict):
                continue
            folded = str(key or "").strip().casefold()
            for candidate in [
                name for name in bucket if str(name or "").strip().casefold() == folded
            ]:
                bucket.pop(candidate, None)

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
    # Kerberos tickets — TGTs only
    # ------------------------------------------------------------------ #
    #
    # Invariant: ``domains_data[domain]["kerberos_tickets"]`` maps a
    # ``username`` to a ccache file that contains a TGT for that user
    # (server == krbtgt/<REALM>@<REALM>, client == username@<REALM>).
    #
    # Service tickets produced by RBCD/S4U/silver-ticket flows MUST be
    # persisted via :meth:`store_service_ticket` instead.  Mixing them in
    # ``kerberos_tickets`` triggered the LDAP fast-path bug where the mere
    # presence of *any* ccache made callers attempt Kerberos auth without a
    # usable ticket for the active user.

    def store_kerberos_ticket(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
        ticket_path: str,
        realm: Optional[str] = None,
        validate: bool = True,
    ) -> bool:
        """Register a Kerberos TGT for *username*.

        Args:
            domains_data: Shared workspace domain mapping.
            domain: Domain key in ``domains_data``.
            username: Principal whose TGT this ccache holds (without realm).
            ticket_path: Filesystem path to the ``.ccache``.
            realm: Optional explicit Kerberos realm.  When omitted the domain
                name (uppercased) is used.
            validate: When ``True`` (default), inspect the ccache and refuse
                to persist if it does not contain a TGT for ``username``.
                Set to ``False`` only for tests or for cases where the caller
                has already validated upstream.

        Returns:
            ``True`` if the entry was persisted, ``False`` when validation
            rejected the ccache.  Callers should treat ``False`` as a real
            failure — it means the produced ccache cannot be used as a TGT.
        """
        from adscan_internal.rich_output import (  # noqa: PLC0415
            mark_sensitive,
            print_warning_debug,
        )

        normalized_user = str(username or "").strip()
        normalized_path = str(ticket_path or "").strip()
        if not normalized_user or not normalized_path:
            return False

        if validate:
            from adscan_internal.services.kerberos_ccache_inspector import (  # noqa: PLC0415
                validate_tgt_for_user,
            )

            effective_realm = (realm or domain or "").strip().upper() or None
            result = validate_tgt_for_user(
                normalized_path, username=normalized_user, realm=effective_realm
            )
            if not result.ok:
                print_warning_debug(
                    f"[kerberos_tickets] refusing to persist {mark_sensitive(normalized_path, 'path')} "
                    f"as TGT for {mark_sensitive(normalized_user, 'user')}@"
                    f"{mark_sensitive(effective_realm or '?', 'domain')}: {result.reason}"
                )
                return False

        domain_data = self.ensure_domain_entry(domains_data, domain)
        tickets = domain_data.setdefault("kerberos_tickets", {})
        tickets[normalized_user] = normalized_path
        return True

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

    # ------------------------------------------------------------------ #
    # Service tickets — RBCD / S4U / constrained delegation / silver tickets
    # ------------------------------------------------------------------ #
    #
    # Stored as a list of ``ServiceTicket.to_dict()`` payloads under
    # ``domains_data[domain]["service_tickets"]``.  Lookups are by SPN /
    # impersonated user / target host.  The same SPN+impersonated_user pair
    # may appear more than once across different attack flows; callers
    # decide which entry to use based on freshness / kind.

    def store_service_ticket(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        ticket: "ServiceTicket",  # noqa: F821 — forward ref, imported below
    ) -> bool:
        """Persist a derived service ticket under *domain*.

        Existing entries with the same ``ccache_path`` are replaced rather
        than duplicated, so reruns of the same attack step keep one row per
        ccache file.
        """
        from adscan_internal.models.service_ticket import (  # noqa: PLC0415
            ServiceTicket,
        )

        if not isinstance(ticket, ServiceTicket):
            raise TypeError(
                "store_service_ticket requires a ServiceTicket instance; "
                f"got {type(ticket).__name__}"
            )
        if not ticket.ccache_path or not ticket.spn:
            return False

        domain_data = self.ensure_domain_entry(domains_data, domain)
        bucket = domain_data.setdefault("service_tickets", [])
        if not isinstance(bucket, list):
            bucket = []
            domain_data["service_tickets"] = bucket

        payload = ticket.to_dict()
        for idx, existing in enumerate(bucket):
            if (
                isinstance(existing, dict)
                and str(existing.get("ccache_path") or "").strip() == ticket.ccache_path
            ):
                bucket[idx] = payload
                return True
        bucket.append(payload)
        return True

    def iter_service_tickets(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        spn: Optional[str] = None,
        impersonated_user: Optional[str] = None,
        target_host: Optional[str] = None,
    ) -> "list[ServiceTicket]":  # noqa: F821 — forward ref
        """Return service tickets for *domain* matching the given filters."""
        from adscan_internal.models.service_ticket import (  # noqa: PLC0415
            ServiceTicket,
        )

        domain_data = domains_data.get(domain, {})
        bucket = (
            domain_data.get("service_tickets", [])
            if isinstance(domain_data, dict)
            else []
        )
        if not isinstance(bucket, list):
            return []

        out: list[ServiceTicket] = []
        for raw in bucket:
            if not isinstance(raw, dict):
                continue
            ticket = ServiceTicket.from_dict(raw)
            if ticket.matches(
                spn=spn,
                impersonated_user=impersonated_user,
                target_host=target_host,
            ):
                out.append(ticket)
        return out

    def delete_service_ticket(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        ccache_path: str,
    ) -> bool:
        """Remove the service ticket entry whose ccache path matches.

        Returns ``True`` if an entry was removed.
        """
        normalized = str(ccache_path or "").strip()
        if not normalized:
            return False
        domain_data = domains_data.get(domain, {})
        bucket = (
            domain_data.get("service_tickets", [])
            if isinstance(domain_data, dict)
            else []
        )
        if not isinstance(bucket, list):
            return False
        for idx, entry in enumerate(bucket):
            if (
                isinstance(entry, dict)
                and str(entry.get("ccache_path") or "").strip() == normalized
            ):
                bucket.pop(idx)
                return True
        return False

    # ------------------------------------------------------------------ #
    # Kerberos key material
    # ------------------------------------------------------------------ #

    def store_kerberos_key_material(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
        nt_hash: str | None = None,
        aes256: str | None = None,
        aes128: str | None = None,
        source: str = "",
        target_host: str = "",
        rid: str = "",
    ) -> KerberosKeyMaterial | None:
        """Store typed Kerberos key material for a principal.

        Args:
            domains_data: Shared workspace domain mapping.
            domain: Domain that owns the principal.
            username: Principal name, e.g. ``krbtgt_8245``.
            nt_hash: Optional RC4/NT hash.
            aes256: Optional AES256 Kerberos key.
            aes128: Optional AES128 Kerberos key.
            source: Optional source identifier for provenance.
            target_host: Optional host that yielded the material.
            rid: Optional RID suffix for per-RODC ``krbtgt_<RID>`` accounts.

        Returns:
            Stored normalized material, or ``None`` when no reusable key was
            provided.
        """
        normalized_username = str(username or "").strip()
        normalized_nt_hash = _normalize_hex_secret(nt_hash, expected_len=32)
        normalized_aes256 = _normalize_hex_secret(aes256, expected_len=64)
        normalized_aes128 = _normalize_hex_secret(aes128, expected_len=32)
        if not normalized_username or (
            not normalized_nt_hash and not normalized_aes256 and not normalized_aes128
        ):
            return None

        domain_data = self.ensure_domain_entry(domains_data, domain)
        kerberos_keys = domain_data.setdefault("kerberos_keys", {})
        # Reuse an existing entry for the same principal regardless of case
        # (AD sAMAccountName is case-insensitive), so a later store under a
        # different casing (e.g. ``dc02$`` after DCSync wrote ``DC02$``) MERGES
        # into the existing record instead of forking a second one that the
        # reader would then have to disambiguate.
        store_key = normalized_username
        current = kerberos_keys.get(store_key)
        if not isinstance(current, dict):
            for candidate in kerberos_keys:
                if (
                    str(candidate or "").strip().casefold()
                    == normalized_username.casefold()
                ):
                    store_key = candidate
                    current = kerberos_keys.get(candidate)
                    break
        current_data = current if isinstance(current, dict) else {}

        material = {
            "nt_hash": normalized_nt_hash or str(current_data.get("nt_hash") or ""),
            "aes256": normalized_aes256 or str(current_data.get("aes256") or ""),
            "aes128": normalized_aes128 or str(current_data.get("aes128") or ""),
            "source": str(source or current_data.get("source") or "").strip(),
            "target_host": str(
                target_host or current_data.get("target_host") or ""
            ).strip(),
            "rid": str(rid or current_data.get("rid") or "").strip(),
        }
        kerberos_keys[store_key] = {
            key: value for key, value in material.items() if value
        }

        return KerberosKeyMaterial(
            username=normalized_username,
            nt_hash=material["nt_hash"] or None,
            aes256=material["aes256"] or None,
            aes128=material["aes128"] or None,
            source=material["source"],
            target_host=material["target_host"],
            rid=material["rid"],
        )

    def get_kerberos_key_material(
        self,
        *,
        domains_data: MutableMapping[str, Any],
        domain: str,
        username: str,
    ) -> KerberosKeyMaterial | None:
        """Return stored Kerberos key material for ``username`` if present.

        Both the domain key and the username key are matched
        CASE-INSENSITIVELY. AD ``sAMAccountName`` (including machine accounts
        like ``DC02$``) is case-insensitive, and the two producers store with
        different casing: DCSync persists the SAMR display name verbatim
        (``DC02$``, uppercase), while a consumer derived from
        ``pdc_hostname_fqdn`` (``dc02.darkzero.ext``) queries ``dc02$``
        (lowercase). A raw ``kerberos_keys.get(username)`` misses that record,
        so the material reads as absent even though it is on disk — the
        cross-org TGT-delegation ``no Kerberos key material held for dc02$``
        abort on a workspace that DOES hold ``DC02$``. Matching by casefold on
        both keys resolves the real record regardless of either producer's
        casing.
        """
        # Resolve the domain and the username keys case-insensitively via the
        # shared SSOT (resolve_ci) — the same principle as the top-level
        # CaseInsensitiveDict, applied at READ time for the nested map so the
        # stored casing (DC02$) is preserved for display.
        domain_data = resolve_ci(domains_data, domain)
        if not isinstance(domain_data, dict):
            return None
        kerberos_keys = domain_data.get("kerberos_keys", {})
        if not isinstance(kerberos_keys, dict):
            return None
        data = resolve_ci(kerberos_keys, username)
        if not isinstance(data, dict):
            return None
        return KerberosKeyMaterial(
            username=username,
            nt_hash=str(data.get("nt_hash") or "") or None,
            aes256=str(data.get("aes256") or "") or None,
            aes128=str(data.get("aes128") or "") or None,
            source=str(data.get("source") or ""),
            target_host=str(data.get("target_host") or ""),
            rid=str(data.get("rid") or ""),
        )

    @staticmethod
    def select_best_kerberos_key(
        material: KerberosKeyMaterial,
    ) -> tuple[str, str] | None:
        """Return the preferred reusable key as ``(kind, value)``.

        AES256 is preferred over AES128, with NT/RC4 as the compatibility
        fallback for older or less hardened domains.
        """
        if material.aes256:
            return "aes256", material.aes256
        if material.aes128:
            return "aes128", material.aes128
        if material.nt_hash:
            return "nt_hash", material.nt_hash
        return None


def looks_like_ntlm_hash(value: object) -> bool:
    """Return True when ``value`` is an NT hash (32 hex) or ``LM:NT`` pair.

    Module-level so a caller outside the service can classify a secret without
    reaching for a protected method or depending on a shell helper that a given
    call site may not have.
    """
    return CredentialStoreService._looks_like_ntlm_hash(value)


def audit_domain_credential_store(
    domains_data: MutableMapping[str, Any],
    domain: str,
    *,
    repair: bool = False,
) -> CredentialStoreConsistencyReport:
    """Report (and optionally repair) divergence between the credential maps.

    ``credentials_meta[user]`` describes the secret in ``credentials[user]``.
    A meta record with no credential is incoherent by construction, and the
    store then contradicts itself: the principal is advertised as recovered
    (``credential_origin`` names the technique, AES keys sit in the record)
    while nothing resolves its secret, so ownership checks read it as NOT
    owned. Surfacing the divergence is cheap; leaving it silent is how a
    destroyed credential looked like a perfectly healthy workspace.

    Repair is strictly additive and restores only material the store ALREADY
    holds: the ``nt_hash`` / ``password`` typed slot becomes the active secret
    again, and recovered Kerberos keys are seeded into the typed
    ``kerberos_keys`` store so AES pass-the-key is usable. A secret is never
    invented, and an orphan with nothing usable left is reported as
    unreconcilable rather than quietly dropped. Scoped to orphans on purpose:
    a coherent principal's key material is left exactly as it is.

    Args:
        domains_data: Shared workspace domain mapping.
        domain: Domain key in ``domains_data``.
        repair: Restore what can be restored, instead of only reporting.

    Returns:
        A :class:`CredentialStoreConsistencyReport`.
    """
    domain_data = resolve_ci(domains_data, domain)
    if not isinstance(domain_data, MutableMapping):
        return CredentialStoreConsistencyReport(domain=domain)
    creds = domain_data.get("credentials")
    meta_map = domain_data.get("credentials_meta")
    if not isinstance(meta_map, dict) or not meta_map:
        return CredentialStoreConsistencyReport(domain=domain)
    if not isinstance(creds, dict):
        creds = {}

    held = {str(name or "").strip().casefold() for name in creds}
    orphans = [
        str(name) for name in meta_map if str(name or "").strip().casefold() not in held
    ]
    if not orphans:
        return CredentialStoreConsistencyReport(domain=domain)
    if not repair:
        return CredentialStoreConsistencyReport(
            domain=domain, orphaned_meta_users=tuple(sorted(orphans))
        )

    store = CredentialStoreService()
    if not isinstance(domain_data.get("credentials"), dict):
        domain_data["credentials"] = {}
    reconciled: list[str] = []
    unreconcilable: list[str] = []
    for name in sorted(orphans):
        record = meta_map.get(name)
        if not isinstance(record, dict):
            unreconcilable.append(name)
            continue
        restored = False
        nt_hash = _normalize_hex_secret(record.get("nt_hash"), expected_len=32)
        password = str(record.get("password") or "").strip()
        secret = nt_hash or password
        if secret:
            domain_data["credentials"][str(name).strip().lower()] = secret
            restored = True
        material = store.store_kerberos_key_material(
            domains_data=domains_data,
            domain=domain,
            username=str(name),
            nt_hash=nt_hash or None,
            aes256=record.get("aes256_key") or record.get("aes256"),
            aes128=record.get("aes128_key") or record.get("aes128"),
            source="credential_store_reconcile",
        )
        if material is not None:
            restored = True
        (reconciled if restored else unreconcilable).append(str(name))

    return CredentialStoreConsistencyReport(
        domain=domain,
        orphaned_meta_users=tuple(sorted(orphans)),
        reconciled_users=tuple(reconciled),
        unreconcilable_users=tuple(unreconcilable),
    )


def _normalize_hex_secret(value: str | None, *, expected_len: int) -> str:
    """Return a lowercase hex secret only when it has the expected length."""
    candidate = str(value or "").strip().lower()
    if len(candidate) != expected_len:
        return ""
    if not re.fullmatch(r"[0-9a-f]+", candidate):
        return ""
    return candidate


# --------------------------------------------------------------------------- #
# Service-ticket persistence + host-scoped resolution (shared, single source)
# --------------------------------------------------------------------------- #
#
# A step that mints a derived service ticket (RBCD/S4U, constrained delegation,
# silver) and a step that later authenticates to the same host both go through
# the helpers below.  Centralising them keeps the producer (delegations.py and
# relay_rbcd.py) and the consumer (attack_path_execution.py) on ONE definition
# of "what is a host match" — the bug this prevents is a ``cifs/WEB01`` ticket
# being mis-used for a DCSync against the DC.


def persist_service_ticket(
    domains_data: MutableMapping[str, Any],
    *,
    domain: str,
    ccache_path: str,
    kind: Any,
    owner_principal: str,
    impersonated_user: str,
    spn: str,
    target_host: str,
) -> bool:
    """Persist an S4U/RBCD/delegation-derived service ticket (single source).

    Parses the resulting ccache via :func:`inspect_ccache` to recover the
    issuance / expiry timestamps and the realm, builds a :class:`ServiceTicket`
    and stores it under ``domains_data[domain]["service_tickets"]`` through
    :meth:`CredentialStoreService.store_service_ticket`.

    This is the DRY core shared by ``delegations._persist_service_ticket_after_s4u``
    and the RBCD chain in ``relay_rbcd._run_s4u`` — both produce host-scoped
    tickets that MUST NOT land in ``kerberos_tickets`` (they are not TGTs).

    Args:
        domains_data: Shared workspace domain mapping.
        domain: Domain key in ``domains_data``.
        ccache_path: Filesystem path to the produced ``.ccache`` file.
        kind: ``ServiceTicketKind`` or a string coercible to one.
        owner_principal: Principal whose TGT/key produced the ST (for RBCD the
            attacker machine account, e.g. ``ADSCANE66DD6$``).
        impersonated_user: The "for client" of the ST (e.g. ``Administrator``).
        spn: Service principal name the ticket grants (e.g.
            ``cifs/web01.example.local``).  When empty, recovered from the
            ccache's first service ticket.
        target_host: Host portion of the SPN, kept separate so consumers can
            match by host without parsing.

    Returns:
        ``True`` when the ticket was persisted, ``False`` otherwise.  Failures
        are swallowed (logged at debug) — a missing persistence is a soft loss
        (the ccache file is still on disk), never worth aborting exploitation.
    """
    from adscan_internal.models.service_ticket import (  # noqa: PLC0415
        ServiceTicket,
        ServiceTicketKind,
    )
    from adscan_internal.services.kerberos_ccache_inspector import (  # noqa: PLC0415
        inspect_ccache,
    )
    from adscan_internal.rich_output import (  # noqa: PLC0415
        mark_sensitive,
        print_info_debug,
    )
    from adscan_core import telemetry  # noqa: PLC0415

    normalized_ccache = str(ccache_path or "").strip()
    if not normalized_ccache:
        return False
    try:
        info = inspect_ccache(normalized_ccache)
        first_st = info.first_service_ticket()
        ticket = ServiceTicket(
            ccache_path=normalized_ccache,
            kind=ServiceTicketKind.coerce(kind),
            owner_principal=str(owner_principal or "").strip()
            or (info.default_client_name or ""),
            impersonated_user=str(impersonated_user or "").strip(),
            spn=str(spn or "").strip() or (first_st.server_spn if first_st else ""),
            target_host=str(target_host or "").strip()
            or _spn_host(first_st.server_spn if first_st else ""),
            realm=(
                (info.default_client_realm or (domain.upper() if domain else ""))
                .strip()
                .upper()
            ),
            etype=getattr(first_st, "etype", None) if first_st else None,
            issued_at=first_st.starttime if first_st else None,
            expires_at=first_st.endtime if first_st else None,
        )
        stored = CredentialStoreService().store_service_ticket(
            domains_data=domains_data,
            domain=domain,
            ticket=ticket,
        )
        if stored:
            print_info_debug(
                f"service_tickets: persisted {mark_sensitive(ticket.ccache_path, 'path')} "
                f"kind={ticket.kind.value} spn={mark_sensitive(ticket.spn, 'service')} "
                f"impersonated={mark_sensitive(ticket.impersonated_user, 'user')}"
            )
        return stored
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"service_tickets: failed to persist {mark_sensitive(normalized_ccache, 'path')}: "
            f"{type(exc).__name__}: {mark_sensitive(str(exc), 'detail')}"
        )
        return False


def _spn_host(spn: str) -> str:
    """Return the host portion of an SPN (``cifs/web01.example.local`` -> host)."""
    raw = str(spn or "").strip()
    if "/" not in raw:
        return ""
    host = raw.split("/", 1)[1].strip()
    # SPNs occasionally carry a port or instance (``host:445``, ``host:inst``).
    return host.split(":", 1)[0].strip()


def host_match_keys(value: str) -> set[str]:
    """Return the alias-aware comparison keys for one host identifier.

    Service-ticket ``target_host`` (an SPN host, usually an FQDN) and the host a
    follow-up step resolves to (FQDN, short name, IP, ``HOST$``, or the attack
    graph's own ``HOST$@REALM`` node label) must compare equal when they denote
    the same machine.  This produces a normalised set so a match is
    ``keys(a) & keys(b)`` being non-empty:

    - lowercased, trailing dot and trailing ``$`` stripped
    - the full value (FQDN or IP)
    - the short hostname (label before the first dot) for non-IP values

    A graph node label (``BRAAVOS$@ESSOS.LOCAL``) is folded into the FQDN it
    denotes (``braavos.essos.local``), so a host identifier read off an
    attack-path step compares equal to the same host stored by a credential or
    ticket writer.  Keeping the realm rather than reducing the label to its
    short name means the FQDN form matches directly.

    IPs are preserved verbatim (no short-name split).  Empty/blank input yields
    an empty set so it never matches anything.
    """
    raw = str(value or "").strip().strip(".").lower()
    if "@" in raw:
        # Attack-graph node label: ``<samaccountname>@<realm>``.
        name, _, realm = raw.partition("@")
        name = name.rstrip("$").strip()
        realm = realm.strip().strip(".")
        raw = f"{name}.{realm}" if name and realm else name
    raw = raw.rstrip("$")
    if not raw:
        return set()
    keys = {raw}
    # IPv4 literal -> keep as-is, do not derive a "short name".
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw):
        return keys
    short = raw.split(".", 1)[0].strip()
    if short:
        keys.add(short)
    return keys


def hosts_match(a: str, b: str) -> bool:
    """Return whether two host identifiers denote the same machine (alias-aware)."""
    keys_a = host_match_keys(a)
    keys_b = host_match_keys(b)
    return bool(keys_a and keys_b and (keys_a & keys_b))


def username_is_host_identifier(username: str, host: str) -> bool:
    """Return whether a local-account username is really the HOST's own name.

    A local credential is keyed by ``(host, service, username)`` where the
    username names an account inside that host's SAM. A computer's name — its
    short name, FQDN, or ``HOST$`` machine account — is a host identifier and
    is never one of those accounts, so a credential filed under it can never
    authenticate.

    This is a defect detector, not a policy: it exists so a path that derives a
    local account name from the wrong field is caught loudly instead of quietly
    producing an unusable principal (which is what happened when a recovered
    LAPS password was stored under the computer name and then discarded as
    "verification failed").
    """
    user = str(username or "").strip()
    if not user or not str(host or "").strip():
        return False
    return hosts_match(user, host)


@dataclass(frozen=True)
class LocalCredentialRecord:
    """One entry of ``domains_data[domain]["local_credentials"]``.

    Carries the full key — ``(host, service, username)`` — because a local
    credential is only meaningful together with the host whose SAM holds the
    account.  A caller that keeps only ``username``/``secret`` has thrown away
    the fact that makes the credential usable at all.
    """

    host: str
    service: str
    username: str
    secret: str


def iter_local_credential_records(
    domains_data: Any, *, domain: str
) -> list[LocalCredentialRecord]:
    """Return every stored local credential for *domain* as a flat list."""
    if not isinstance(domains_data, dict):
        return []
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return []
    local_creds = domain_data.get("local_credentials")
    if not isinstance(local_creds, dict):
        return []
    records: list[LocalCredentialRecord] = []
    for host, services in local_creds.items():
        if not isinstance(services, dict):
            continue
        for service, users in services.items():
            if not isinstance(users, dict):
                continue
            for username, secret in users.items():
                if not isinstance(secret, str) or not secret.strip():
                    continue
                records.append(
                    LocalCredentialRecord(
                        host=str(host or "").strip(),
                        service=str(service or "").strip(),
                        username=str(username or "").strip(),
                        secret=secret,
                    )
                )
    return records


def find_local_credential_record(
    domains_data: Any,
    *,
    domain: str,
    username: str,
    secret: Optional[str] = None,
    host_aliases: Optional[set[str]] = None,
    service: Optional[str] = None,
) -> Optional[LocalCredentialRecord]:
    """Return the local-credential entry matching the given key, if any.

    Every filter is optional and additive:

    * ``username`` — always applied, case/realm-insensitive.
    * ``secret`` — exact value match.  Used to answer "is the credential I am
      holding a LOCAL one?" without guessing.
    * ``host_aliases`` — the alias set from :func:`expand_host_query_aliases`;
      the record's host must alias one of them.
    * ``service`` — ``smb`` / ``mssql`` / ``winrm`` / ``rdp``.

    Returns ``None`` rather than a best guess: a wrong local credential
    authenticates against the wrong authority, so an unresolved query must not
    silently degrade into "some credential with the same name".
    """
    target_user = _normalize_marker_user(username)
    if not target_user:
        return None
    wanted_service = str(service or "").strip().lower() or None
    for record in iter_local_credential_records(domains_data, domain=domain):
        if _normalize_marker_user(record.username) != target_user:
            continue
        if secret is not None and record.secret != secret:
            continue
        if wanted_service and record.service.lower() != wanted_service:
            continue
        if host_aliases is not None and not any(
            hosts_match(record.host, alias) for alias in host_aliases
        ):
            continue
        return record
    return None


def resolve_local_credential_for_host(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    service: Optional[str] = None,
) -> Optional[LocalCredentialRecord]:
    """Return a local credential for *username* in *host*'s SAM, if stored.

    The host-scoped sibling of the domain-only stored-credential resolver.  It
    is what lets a step that authenticates to a host use an account that exists
    only inside that host — a local Administrator recovered from LAPS or a SAM
    dump — instead of a same-named domain principal, which is a different
    account with a different password.

    Host matching goes through :func:`expand_host_query_aliases`, so the step's
    host (label, short name, FQDN or IP) matches the form the credential was
    stored under.
    """
    aliases = expand_host_query_aliases(shell, domain=domain, host=host)
    if not aliases:
        return None
    return find_local_credential_record(
        getattr(shell, "domains_data", None),
        domain=domain,
        username=username,
        host_aliases=aliases,
        service=service,
    )


# ---------------------------------------------------------------------------
# Logon-capability negative cache — "principal X cannot <logon_type> on host Y".
#
# Some principals hold a privilege (e.g. a Domain Admin has replication rights)
# yet the TARGET denies them the LOGON TYPE needed to use it — the DC returns
# STATUS_LOGON_TYPE_NOT_GRANTED at SMB session_setup (a SeDenyNetworkLogonRight /
# "Deny access to this computer from the network" hardening). This is NOT
# readable from a simple LDAP attribute (it lives in User Rights Assignment —
# local policy or GPO/SYSVOL), so the ground truth is the logon attempt itself.
#
# When an ST flow (RBCD/AllowedToAct, KCD/SPNJack, silver) or a consuming step
# (DCSync, DumpLSA) observes a logon-type denial for an impersonated principal,
# it records it here so that principal is never re-selected for an ST against
# that host in ANY flow — mirrors how Protected Users are excluded, but learned
# reactively from ground truth. Alias-aware on the host (IP <-> short <-> FQDN
# <-> HOST$). Persisted JSON-safe in ``domains_data[domain]["logon_denied"]``.
# ---------------------------------------------------------------------------

_DEFAULT_LOGON_TYPE = "network"


def _logon_principal_key(value: str) -> str:
    """Normalize a principal to a bare, lowercased account name for matching.

    Strips ``DOMAIN\\`` prefix and ``@realm`` suffix; PRESERVES a trailing ``$``
    (it distinguishes a machine account like ``dc01$`` from a user).
    """
    v = str(value or "").strip().lower()
    if "\\" in v:
        v = v.rsplit("\\", 1)[-1]
    if "@" in v:
        v = v.split("@", 1)[0]
    return v.strip()


def is_logon_denied(
    domains_data: dict,
    domain: str,
    *,
    principal: str,
    host: str,
    logon_type: str = _DEFAULT_LOGON_TYPE,
) -> bool:
    """Return True when ``principal`` is known-denied ``logon_type`` on ``host``.

    Alias-aware on the host; principal matched on its bare account name.
    """
    bucket = (domains_data.get(domain) or {}).get("logon_denied") or []
    if not isinstance(bucket, list):
        return False
    want_p = _logon_principal_key(principal)
    if not want_p or not str(host or "").strip():
        return False
    for rec in bucket:
        if not isinstance(rec, dict):
            continue
        if str(rec.get("logon_type") or _DEFAULT_LOGON_TYPE) != logon_type:
            continue
        if _logon_principal_key(rec.get("principal") or "") != want_p:
            continue
        if hosts_match(str(rec.get("host") or ""), host):
            return True
    return False


def logon_denied_principals_for_host(
    domains_data: dict,
    domain: str,
    *,
    host: str,
    logon_type: str = _DEFAULT_LOGON_TYPE,
) -> set[str]:
    """Return the bare account keys known-denied ``logon_type`` on ``host``.

    Alias-aware on the host. Lets a selector exclude every principal that the
    target has already refused (ground truth from a prior probe), so a re-run
    never re-offers a dead principal for an ST flow against that host.
    """
    denied: set[str] = set()
    bucket = (domains_data.get(domain) or {}).get("logon_denied") or []
    if not isinstance(bucket, list) or not str(host or "").strip():
        return denied
    for rec in bucket:
        if not isinstance(rec, dict):
            continue
        if str(rec.get("logon_type") or _DEFAULT_LOGON_TYPE) != logon_type:
            continue
        key = _logon_principal_key(rec.get("principal") or "")
        if key and hosts_match(str(rec.get("host") or ""), host):
            denied.add(key)
    return denied


def filter_logon_capable_principals(
    domains_data: dict,
    domain: str,
    *,
    host: str,
    candidates: list[str],
    logon_type: str = _DEFAULT_LOGON_TYPE,
) -> list[str]:
    """Drop principals known-denied ``logon_type`` on ``host`` (order preserved).

    Use at a principal-selection seam for a NETWORK-authenticating step (SMB /
    WinRM / RDP) that has a clear fallback and can afford to drop dead principals
    entirely. Alias-aware on host and principal. Returns a NEW list. Do NOT use
    for TGT/AS-REQ or scoped-ticket flows — the denial is network-logon-specific.
    """
    denied = logon_denied_principals_for_host(
        domains_data, domain, host=host, logon_type=logon_type
    )
    if not denied:
        return list(candidates)
    return [c for c in candidates if _logon_principal_key(c) not in denied]


def order_logon_capable_first(
    domains_data: dict,
    domain: str,
    *,
    host: str,
    candidates: list[str],
    logon_type: str = _DEFAULT_LOGON_TYPE,
) -> list[str]:
    """Reorder so known-denied principals sink to the end (kept as last resort).

    The safe primitive for auto-pick steps that must NEVER end with zero
    candidates: a principal the host has already refused a network logon is
    deprioritized (so a logon-capable one is tried first) but retained at the
    tail, so the step still has something to try if every candidate is denied.
    Order is otherwise preserved; relative order within each bucket is stable.
    Alias-aware. Network-logon steps only — never gate TGT/AS-REQ/scoped-ticket.
    """
    denied = logon_denied_principals_for_host(
        domains_data, domain, host=host, logon_type=logon_type
    )
    if not denied:
        return list(candidates)
    capable = [c for c in candidates if _logon_principal_key(c) not in denied]
    blocked = [c for c in candidates if _logon_principal_key(c) in denied]
    return capable + blocked


def mark_logon_denied(
    domains_data: dict,
    domain: str,
    *,
    principal: str,
    host: str,
    logon_type: str = _DEFAULT_LOGON_TYPE,
    reason: str | None = None,
) -> bool:
    """Record that ``principal`` is denied ``logon_type`` on ``host`` (ground truth).

    Idempotent (alias-aware dedup). Returns True when a new record was added.
    No-op for blank principal/host. The record is JSON-safe for persistence.
    """
    if not _logon_principal_key(principal) or not str(host or "").strip():
        return False
    if is_logon_denied(
        domains_data, domain, principal=principal, host=host, logon_type=logon_type
    ):
        return False
    domain_entry = domains_data.setdefault(domain, {})
    if not isinstance(domain_entry, dict):
        return False
    bucket = domain_entry.setdefault("logon_denied", [])
    if not isinstance(bucket, list):
        bucket = []
        domain_entry["logon_denied"] = bucket
    bucket.append(
        {
            "principal": _logon_principal_key(principal),
            "host": str(host).strip(),
            "logon_type": logon_type,
            "reason": str(reason) if reason else None,
        }
    )
    return True


def status_is_logon_type_denied(status_text: str) -> bool:
    """Classify an auth-failure string as a LOGON-TYPE denial (worth caching).

    Distinguishes a deterministic logon-rights refusal (the principal will keep
    being refused → cache it) from a transient/connectivity error (do NOT cache).
    """
    s = str(status_text or "").lower()
    return any(
        marker in s
        for marker in (
            "logon_type_not_granted",
            "logon type not granted",
            "0xc000015b",
            "1385",  # ERROR_LOGON_TYPE_NOT_GRANTED (Win32)
        )
    )


def expand_host_query_aliases(shell: Any, *, domain: str, host: str) -> set[str]:
    """Return every identifier that denotes *host*, bridging IP <-> hostname.

    :func:`host_match_keys` is string-only (it deliberately keeps IPs verbatim),
    so an IP can never alias-match an FQDN.  But a host-scoped artefact — a
    service ticket keyed by its SPN host, a local credential keyed by the host
    it was captured on — is usually stored under a name while the step that
    wants it often knows the host only by IP (or the reverse).  This expands the
    query host through the persisted workspace IP/hostname inventory so both
    directions match.

    Best-effort: with no inventory the result is just ``{host}``, which behaves
    exactly like a direct :func:`hosts_match`.
    """
    normalized_host = str(host or "").strip()
    if not normalized_host:
        return set()
    query_hosts: set[str] = {normalized_host}
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (  # noqa: PLC0415
            load_workspace_ip_hostname_inventory,
        )

        inventory = (
            load_workspace_ip_hostname_inventory(
                workspace_dir=getattr(shell, "current_workspace_dir", "") or "",
                domains_dir=getattr(shell, "domains_dir", "domains") or "domains",
                domain=domain,
            )
            or {}
        )
        nh_low = normalized_host.lower().rstrip(".").rstrip("$")
        nh_short = nh_low.split(".", 1)[0]
        for ip, names in inventory.items():
            names_low = {str(n).lower().rstrip(".") for n in (names or [])}
            shorts = {n.split(".", 1)[0] for n in names_low}
            if nh_low == str(ip).lower() or nh_low in names_low or nh_short in shorts:
                query_hosts.add(str(ip))
                query_hosts.update(names or [])
    except Exception:  # noqa: BLE001 — inventory bridge is best-effort
        pass
    return query_hosts


def resolve_scoped_ticket_for_host(
    shell: Any,
    *,
    domain: str,
    host: str,
    service: str = "cifs",
) -> Optional[tuple[str, str]]:
    """Return the best stored service ticket scoped to *host*, if any.

    Walks ``domains_data[domain]["service_tickets"]`` and returns the newest,
    non-expired ticket whose ``target_host`` (or SPN host) is an alias of
    *host*.  This is the consumer half of the service-ticket handoff: a step
    that authenticates to a host (DumpLSA, DumpDPAPI, DCSync, …) calls this
    BEFORE the generic credential resolver and, on a hit, runs as the ticket's
    ``impersonated_user`` with the ticket's ccache.

    The alias-aware host match (:func:`hosts_match`) is exactly what stops a
    ``cifs/WEB01`` ticket from being handed to a DCSync against the DC: a
    different ``target_host`` yields no match, so the caller falls back to the
    generic resolver.

    Args:
        shell: Shell exposing ``domains_data``.
        domain: Domain key in ``domains_data``.
        host: Target host the follow-up step resolved to (FQDN/IP/short/``HOST$``).
        service: Optional service prefix filter (default ``cifs``).  When set,
            only tickets whose SPN service matches are considered; pass ``""``
            to accept any service.

    Returns:
        ``(impersonated_user, ccache_path)`` for the best match, or ``None``.
    """
    normalized_host = str(host or "").strip()
    if not normalized_host:
        return None
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None

    tickets = CredentialStoreService().iter_service_tickets(
        domains_data=domains_data,
        domain=domain,
    )
    if not tickets:
        return None

    service_prefix = str(service or "").strip().lower()
    import time  # noqa: PLC0415

    now = int(time.time())

    # IP<->FQDN bridge. A scoped ticket is stored under its SPN host (an FQDN,
    # e.g. ldap/DC01.pirate.htb) while a follow-up step often knows the host only
    # by IP (domains_data may carry only `pdc`/dc_ip, no dc_fqdn — exactly the
    # DCSync-after-SPNJack case).
    query_hosts = expand_host_query_aliases(shell, domain=domain, host=normalized_host)

    candidates: list = []
    for ticket in tickets:
        if not ticket.ccache_path or not ticket.impersonated_user:
            continue
        if service_prefix:
            spn_service = (
                ticket.spn.split("/", 1)[0].strip().lower() if ticket.spn else ""
            )
            if spn_service and spn_service != service_prefix:
                continue
        # Host match: prefer the explicit target_host, fall back to the SPN host.
        # Match against any bridged form of the query host (IP<->FQDN aliases).
        ticket_host = ticket.target_host or _spn_host(ticket.spn)
        if not any(hosts_match(ticket_host, qh) for qh in query_hosts):
            continue
        # Drop tickets we know are expired; keep tickets with unknown expiry
        # (a None expiry means the ccache was unparseable for times — the file
        # is still the source of truth and may be valid).
        if ticket.expires_at is not None and ticket.expires_at <= now:
            continue
        candidates.append(ticket)

    if not candidates:
        return None

    # Newest first: prefer the most recently issued ticket; ties broken by the
    # later expiry.  Unknown timestamps sort last (treated as oldest).
    def _sort_key(t) -> tuple[int, int]:
        return (t.issued_at or 0, t.expires_at or 0)

    best = max(candidates, key=_sort_key)
    return best.impersonated_user, best.ccache_path


# --------------------------------------------------------------------------- #
# Relation -> Kerberos service map (the consumer's "which ST do I need?")
# --------------------------------------------------------------------------- #
#
# A step that authenticates to a host must consume a service ticket whose SPN
# class matches the service its transport actually binds — NOT a guess. Before
# this map the two scoped-ticket consumers hard-wired their service string
# inline, and one was wrong: DCSync passed ``service="ldap"`` even though the
# native DRSUAPI replication runs over an aiosmb SMB connection
# (``smb_machine_with_fallback`` in ``native_dump_service.dcsync`` →
# ``cifs/<dc>``). It only worked because the SPNJack-minted ccaches carried the
# administrator TGT, so the SMB bind could derive ``cifs/<dc>`` regardless of
# the filter — luck, not design. A pure ldap service ticket (no TGT) would have
# selected "right" by the filter and then failed the cifs bind.
#
# This is the single source of truth for "relation -> Kerberos service class".
# Keys are lowercase relation/action strings (the same strings the attack-path
# engine and ACE executor dispatch on). Values are lowercase SPN service
# prefixes, matched against ``ServiceTicket.spn.split('/')[0].lower()`` by
# :func:`resolve_scoped_ticket_for_host`.
#
# DRSUAPI / dump steps -> cifs (all authenticate via an aiosmb SMB connection):
#   * dcsync     -> DRSUAPI GetNCChanges over SMB
#   * dumplsa    -> LSASS dump over SMB
#   * dumpdpapi  -> DPAPI material over SMB
#   * dumpsam    -> SAM/SYSTEM hive over SMB
#
# Lateral access steps -> the protocol's own SPN class. These are NOT wired as
# scoped-ticket consumers yet (their native verifiers classify only
# password-vs-NT-hash and do not detect a .ccache credential — see the Phase 2
# entry in BACKLOG.md). The rows live here so that when each verifier is taught
# to route a ccache, wiring the consumer is a one-line change and the service
# class is already correct by construction:
#   * adminto / hassession -> cifs   (SMB local-admin)
#   * canpsremote          -> http   (WinRM / WSMAN: HTTP/<host>)
#   * canrdp               -> termsrv
#   * sqladmin / sqlaccess -> mssqlsvc
_DEFAULT_KERBEROS_SERVICE = "cifs"

RELATION_TO_KERBEROS_SERVICE: dict[str, str] = {
    # DRSUAPI / dump family — all bind over SMB.
    "dcsync": "cifs",
    "dumplsa": "cifs",
    "dumpdpapi": "cifs",
    "dumpsam": "cifs",
    # Lateral access family (Phase 2 — see BACKLOG.md).
    "adminto": "cifs",
    "hassession": "cifs",
    "canpsremote": "http",
    "canrdp": "termsrv",
    "sqladmin": "mssqlsvc",
    "sqlaccess": "mssqlsvc",
}


def kerberos_service_for_relation(relation: str) -> str:
    """Return the Kerberos SPN service class a *relation* authenticates with.

    Single source of truth for "which service ticket does the next step need".
    Falls back to ``cifs`` for unknown relations — the safest default because a
    ccache that carries a TGT can mint a ``cifs`` ticket for the host, and most
    post-ex steps bind over SMB.

    Args:
        relation: Lowercase (or any-case) relation/action string, e.g.
            ``"dcsync"``, ``"dumplsa"``, ``"canpsremote"``.

    Returns:
        Lowercase SPN service prefix (``"cifs"``, ``"http"``, ``"termsrv"``,
        ``"mssqlsvc"``, ``"ldap"``, …).
    """
    return RELATION_TO_KERBEROS_SERVICE.get(
        str(relation or "").strip().lower(), _DEFAULT_KERBEROS_SERVICE
    )


def resolve_execution_credential(
    shell: Any,
    *,
    domain: str,
    host: str,
    relation: str,
) -> Optional[tuple[str, str]]:
    """Return the best host-scoped service ticket for the NEXT step, or ``None``.

    The single entry point a chained step should call to reuse a service ticket
    minted by a prior step (RBCD/S4U2Proxy, constrained delegation, SPNJack,
    silver). It combines two pieces that used to be hand-wired at each call
    site:

      1. **Service correctness** — derives the Kerberos service class from
         *relation* via :func:`kerberos_service_for_relation`, so DCSync asks
         for ``cifs`` (DRSUAPI-over-SMB), DumpLSA for ``cifs``, a future WinRM
         consumer for ``http`` — correct by construction, never a guess.

      2. **Preferent matching** — first looks for a ticket whose SPN service
         already matches (the exact ticket for this step); on no match, falls
         back to *any* non-expired ticket for the host. This avoids a false
         negative: a ccache that carries the principal's TGT is usable for any
         service on the host, so rejecting it merely because its SPN prefix is
         ``ldap`` rather than ``cifs`` would be wrong. The service class is a
         preference (and tie-breaker), not a hard gate.

    On ``None`` the caller falls back to its generic credential resolver
    (password/NT-hash for the execution principal) exactly as before.

    Args:
        shell: Shell exposing ``domains_data`` (and workspace paths for the
            IP↔FQDN bridge inside :func:`resolve_scoped_ticket_for_host`).
        domain: Domain key in ``domains_data``.
        host: Target host the follow-up step resolved to (FQDN/IP/short/``HOST$``).
        relation: The relation/action of the step about to authenticate
            (``"dcsync"``, ``"dumplsa"``, …). Selects the preferred service.

    Returns:
        ``(impersonated_user, ccache_path)`` for the best match, or ``None``.
    """
    service = kerberos_service_for_relation(relation)
    # Preferent: a ticket whose SPN class already matches this step wins.
    hit = resolve_scoped_ticket_for_host(
        shell, domain=domain, host=host, service=service
    )
    if hit is not None:
        return hit
    # No service-matched ticket — accept any non-expired ticket for this host
    # (a ccache carrying the TGT serves every service on the host).
    return resolve_scoped_ticket_for_host(shell, domain=domain, host=host, service="")


# --------------------------------------------------------------------------- #
# Capability-bearing TGT marker (ESC13 / Pass-the-Certificate)
# --------------------------------------------------------------------------- #
#
# Most TGT ccaches in ``kerberos_tickets`` are interchangeable with a stored
# password/hash for the same principal, so the generic resolver prefers the
# password (it is reusable, the ccache may be expired).  ESC13 PtC is the
# exception: the minted TGT carries a synthetic group SID in its PAC that the
# password CANNOT reproduce.  Dropping that ccache for the password on re-auth
# silently discards the ESC13 privilege.
#
# This marker records, per user, the ccache that MUST be preferred over a
# password/hash for that user.  It is a plain ``{user: ccache_path}`` map
# (JSON-safe) under ``domains_data[domain]["capability_bearing_ccache"]`` and
# is honoured ONLY by the resolver for the marked user — the global
# password-first default is unchanged for every other flow.

_CAPABILITY_BEARING_KEY = "capability_bearing_ccache"


def _normalize_marker_user(username: str) -> str:
    """Normalize a principal name for keyed lookups in this module.

    Lowercase, ``DOMAIN\\`` prefix and ``@realm`` suffix removed, and any
    zero-width sensitivity markers stripped first — a name that reached here
    through a marked display string would otherwise never match its stored key.
    """
    name = strip_sensitive_markers(str(username or "")).strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def mark_capability_bearing_ccache(
    domains_data: MutableMapping[str, Any],
    *,
    domain: str,
    username: str,
    ccache_path: str,
) -> bool:
    """Mark *ccache_path* as the prefer-over-password ccache for *username*.

    Used by the ESC13 / Pass-the-Certificate flow when the minted TGT carries a
    synthetic group SID in its PAC.  Returns ``True`` when the marker was
    written.
    """
    normalized_user = _normalize_marker_user(username)
    normalized_path = str(ccache_path or "").strip()
    if not normalized_user or not normalized_path:
        return False
    domain_data = CredentialStoreService.ensure_domain_entry(domains_data, domain)
    marker = domain_data.setdefault(_CAPABILITY_BEARING_KEY, {})
    if not isinstance(marker, dict):
        marker = {}
        domain_data[_CAPABILITY_BEARING_KEY] = marker
    marker[normalized_user] = normalized_path
    return True


def get_capability_bearing_ccache(
    domains_data: Any,
    *,
    domain: str,
    username: str,
) -> Optional[str]:
    """Return the prefer-over-password ccache for *username*, if marked.

    Returns the marked ccache path only when the user has an explicit marker
    AND the path is non-empty; otherwise ``None`` (the caller keeps the global
    password-first default).
    """
    if not isinstance(domains_data, dict):
        return None
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return None
    marker = domain_data.get(_CAPABILITY_BEARING_KEY)
    if not isinstance(marker, dict):
        return None
    target = _normalize_marker_user(username)
    if not target:
        return None
    for stored_user, path in marker.items():
        if _normalize_marker_user(str(stored_user)) != target:
            continue
        text = str(path or "").strip()
        return text or None
    return None


def get_stored_domain_credential_for_user(
    domains_data: Any,
    *,
    domain: str,
    username: str,
) -> Optional[str]:
    """Return the stored credential for a domain principal, or ``None``.

    The one answer to "does ADscan hold something that can authenticate as this
    principal", in preference order:

    1. a capability-bearing ccache explicitly marked prefer-over-password for
       this user (ESC13 / Pass-the-Certificate — the password cannot reproduce
       the synthetic PAC group SID);
    2. a password / NT hash from ``credentials``;
    3. a registered Kerberos ccache from ``kerberos_tickets`` — the
       NTLM-disabled / AES-only case, where a PKINIT TGT is the only usable
       credential. The ccache path is itself a valid credential: downstream
       Kerberos-backed steps (DCSync/DRSUAPI, LDAP, SMB) accept and select it.

    A blank ``credentials`` entry is NOT a credential: the lookup falls through
    to the ccache rather than returning an empty string, so "stored" never means
    "present but unusable".

    Args:
        domains_data: The shell's ``domains_data`` mapping.
        domain: Domain the principal belongs to.
        username: Principal name in any form (``DOMAIN\\user``, ``user@realm``,
            bare sAMAccountName, marked or unmarked).

    Returns:
        The credential (password, NT hash, or ccache path), or ``None``.
    """
    normalized_target = _normalize_marker_user(username)
    if not normalized_target or not isinstance(domains_data, dict):
        return None
    capability_ccache = get_capability_bearing_ccache(
        domains_data, domain=domain, username=normalized_target
    )
    if capability_ccache:
        return capability_ccache
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return None
    credentials = domain_data.get("credentials")
    if isinstance(credentials, dict):
        for stored_user, stored_credential in credentials.items():
            if _normalize_marker_user(str(stored_user)) != normalized_target:
                continue
            if isinstance(stored_credential, str) and stored_credential.strip():
                return stored_credential.strip()
            break
    kerberos_tickets = domain_data.get("kerberos_tickets")
    if isinstance(kerberos_tickets, dict):
        for stored_user, ticket_path in kerberos_tickets.items():
            if _normalize_marker_user(str(stored_user)) != normalized_target:
                continue
            if isinstance(ticket_path, str) and ticket_path.strip():
                return ticket_path.strip()
            break
    return None


__all__ = [
    "CredentialStoreService",
    "DomainCredentialUpdateResult",
    "KerberosKeyMaterial",
    "LocalCredentialUpdateResult",
    "persist_service_ticket",
    "resolve_scoped_ticket_for_host",
    "resolve_execution_credential",
    "kerberos_service_for_relation",
    "RELATION_TO_KERBEROS_SERVICE",
    "LocalCredentialRecord",
    "expand_host_query_aliases",
    "find_local_credential_record",
    "iter_local_credential_records",
    "resolve_local_credential_for_host",
    "host_match_keys",
    "hosts_match",
    "filter_logon_capable_principals",
    "is_logon_denied",
    "logon_denied_principals_for_host",
    "mark_logon_denied",
    "order_logon_capable_first",
    "status_is_logon_type_denied",
    "mark_capability_bearing_ccache",
    "get_capability_bearing_ccache",
    "get_stored_domain_credential_for_user",
]
