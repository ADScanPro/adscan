"""Credential context + invalidation registry for Kerberos PAC freshness.

Problem this module solves
==========================

A pentesting workflow chains privilege-granting steps:

    Step 1: AddMember(svc-alfresco -> Exchange Trusted Subsystem)
    Step 2: WriteDACL(DC=htb,DC=local) using svc-alfresco's TGT
            -> insufficientAccessRights

Step 2 fails because the TGT cached in svc-alfresco's ccache was minted
**before** Step 1 modified group membership.  The PAC inside that TGT does
not contain the new group SIDs, so the DC's access token is built without
the privileges that the on-disk ACL says svc-alfresco now has.  The wire
ACL is correct; the failure is purely PAC freshness.

Design — defence in depth
=========================

Three layered staleness criteria, evaluated in this order inside
``refresh_if_stale``:

1. **Wall-clock timestamp** (primary).  ``CredentialRegistry`` records the
   timestamp of every invalidation.  If the on-disk ccache's mtime is older
   than the latest invalidation that could have affected this principal, the
   ticket is stale regardless of when the context was constructed.  This is
   the invariant that survives "context built after invalidation" races —
   the ccache file pre-dates the mutation, so it cannot contain its effects.

2. **Epoch counter** (fallback).  Kept for back-compat and for the case where
   the ccache file does not exist on disk yet.  Compares the registry's
   current epoch against ``issued_at_epoch`` snapshotted at TGT-mint time.

3. **Force flag**.  ``refresh_if_stale(force=True)`` skips both checks and
   refreshes unconditionally.  Used by the transport-level auto-retry
   (``services/auth/auth_retry.py``) when a bind raises
   ``insufficientAccessRights`` despite the staleness checks above passing.

Both primitives below are async-friendly but synchronous-callable:
``refresh_if_stale`` is an ``async def`` so the LDAP / Kerberos transports
(already async) can call it without blocking the loop.  Sync callers go
through ``ADscanLDAPConnection.__enter__`` which already drives the loop.

Cross-domain
============

Epochs and timestamps are tracked per ``(principal, realm)`` AND per realm.
``epoch_for`` and ``last_invalidate_at_for`` return ``max(principal, realm)``
so a realm-wide invalidation transparently invalidates every principal.  A
``invalidate_domain`` helper covers structural mutations (AdminSDHolder,
domain-wide password resets) that affect every principal in a realm.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import threading
import time
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_info_verbose,
    print_warning,
)
from adscan_core.rich_output import print_exception


def _epoch_key(principal: str, realm: str) -> tuple[str, str]:
    """Normalize an epoch lookup key.

    Both halves are case-folded — SIDs are case-insensitive, AD realms are
    case-insensitive.  An empty ``principal`` (callers that do not yet know
    the SID) folds to the empty string and shares one global slot per realm,
    which is conservative: any invalidation on the realm forces a refresh.
    """
    return (str(principal or "").strip().casefold(), str(realm or "").strip().casefold())


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class CredentialRegistry:
    """Process-global "PAC freshness" tracker (epoch + wall-clock timestamp).

    The registry never holds credentials.  Every mutator that could invalidate
    a cached PAC calls :meth:`invalidate` (per principal) or
    :meth:`invalidate_domain` (per realm).  Both bump an epoch counter **and**
    record a wall-clock timestamp; transports compare the timestamp against the
    ccache's mtime (primary) and the epoch against the bound context's snapshot
    (fallback) before each bind.
    """

    def __init__(self) -> None:
        self._epochs: dict[tuple[str, str], int] = {}
        self._domain_epochs: dict[str, int] = {}
        self._last_invalidate_at: dict[tuple[str, str], float] = {}
        self._domain_last_invalidate_at: dict[str, float] = {}
        self._lock = threading.Lock()

    # -- Reads ---------------------------------------------------------------

    def epoch_for(self, principal: str, realm: str) -> int:
        """Return the current epoch for one ``(principal, realm)`` pair.

        The effective epoch is the max of the per-pair counter and the
        realm-wide counter, so a domain-wide invalidation transparently
        invalidates every principal in that realm without touching individual
        per-principal slots.
        """
        key = _epoch_key(principal, realm)
        with self._lock:
            pair_epoch = self._epochs.get(key, 0)
            realm_epoch = self._domain_epochs.get(key[1], 0)
        return max(pair_epoch, realm_epoch)

    def last_invalidate_at_for(self, principal: str, realm: str) -> float | None:
        """Return the most recent invalidation timestamp affecting this principal.

        Returns the ``max`` of the per-principal and per-realm timestamps when
        either is set, ``None`` if nothing has invalidated this principal yet.
        Wall-clock seconds (``time.time()``).
        """
        key = _epoch_key(principal, realm)
        with self._lock:
            pair_ts = self._last_invalidate_at.get(key)
            realm_ts = self._domain_last_invalidate_at.get(key[1])
        if pair_ts is None and realm_ts is None:
            return None
        if pair_ts is None:
            return realm_ts
        if realm_ts is None:
            return pair_ts
        return max(pair_ts, realm_ts)

    # -- Writes --------------------------------------------------------------

    def invalidate(self, principal: str, realm: str, *, reason: str) -> int:
        """Bump the epoch for one principal, returning the new value.

        ``reason`` is a short stable identifier (``"added_to_group"``,
        ``"force_change_password"``, ``"add_key_credential_link"``, ...).
        It is logged so the trace shows why a refresh fired.
        """
        key = _epoch_key(principal, realm)
        now = time.time()
        with self._lock:
            new_value = self._epochs.get(key, 0) + 1
            self._epochs[key] = new_value
            self._last_invalidate_at[key] = now
        print_info_debug(
            "[cred-registry] invalidate principal="
            f"{mark_sensitive(principal, 'user')} "
            f"realm={mark_sensitive(realm, 'domain')} "
            f"reason={reason} epoch={new_value} ts={now:.3f}"
        )
        return new_value

    def invalidate_domain(self, realm: str, *, reason: str) -> int:
        """Bump the realm-wide epoch.  Use for AdminSDHolder writes,
        cross-cutting password resets, krbtgt resets, and other mutations
        that affect every principal in the realm at once.
        """
        realm_key = str(realm or "").strip().casefold()
        now = time.time()
        with self._lock:
            new_value = self._domain_epochs.get(realm_key, 0) + 1
            self._domain_epochs[realm_key] = new_value
            self._domain_last_invalidate_at[realm_key] = now
        print_info_debug(
            "[cred-registry] invalidate domain="
            f"{mark_sensitive(realm, 'domain')} reason={reason} "
            f"epoch={new_value} ts={now:.3f}"
        )
        return new_value


_GLOBAL_REGISTRY: CredentialRegistry | None = None
_GLOBAL_REGISTRY_LOCK = threading.Lock()


def get_credential_registry() -> CredentialRegistry:
    """Return the process-wide registry singleton.

    A singleton is appropriate here because:
    - the engagement runs in a single workspace at a time,
    - epochs are intentionally process-global so a write performed in one
      service can be observed by every transport in the same process,
    - tests that need isolation should construct ``CredentialRegistry()``
      directly instead of touching the singleton.
    """
    global _GLOBAL_REGISTRY
    if _GLOBAL_REGISTRY is None:
        with _GLOBAL_REGISTRY_LOCK:
            if _GLOBAL_REGISTRY is None:
                _GLOBAL_REGISTRY = CredentialRegistry()
    return _GLOBAL_REGISTRY


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


@dataclass
class CredentialContext:
    """Bind-time credential snapshot, refreshable against a registry.

    A context is constructed where the secret is known (CLI exploit handler,
    attack-path step runtime) and forwarded down through transports.  The
    transports are responsible for calling :meth:`refresh_if_stale` exactly
    once per bind, immediately before the AS-REQ / bind happens.

    Fields:
        principal_sid: SID (preferred) or sAMAccountName of the principal
            owning the credential.  Used as the registry key.  Empty value
            falls back to ``username`` when comparing epochs.
        username: sAMAccountName for AS-REQ.  Required.
        auth_domain: realm where the credential lives (KDC realm of the
            TGT).  Cross-domain attacks: this is **not** the target domain.
        password: cleartext password (preferred for AES-only KDCs).
        nt_hash: NTLM hash, used as fallback if no password is available.
        aes_key: AES-128 (32 hex) or AES-256 (64 hex) Kerberos key.
        ccache_path: filesystem path to the workspace ccache that backs the
            bind.  Updated in place on a successful refresh.
        workspace_dir: root for ``KerberosTicketService.auto_generate_tgt``
            so the ccache is written next to the existing one.
        dc_ip: KDC for ``auth_domain`` (the AS-REQ destination).
        issued_at_epoch: the registry epoch observed when this context's
            current TGT was minted.  Bumped after a successful refresh.
    """

    principal_sid: str
    username: str
    auth_domain: str
    password: str | None = None
    nt_hash: str | None = None
    aes_key: str | None = None
    ccache_path: str | None = None
    workspace_dir: str | None = None
    dc_ip: str | None = None
    issued_at_epoch: int = 0
    # Per-instance lock so two coroutines that both call refresh_if_stale on
    # the same context do not double-mint a TGT.
    _refresh_lock: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        # ``threading.Lock`` is fine even from async code: refresh holds it
        # for the duration of one synchronous KerberosTicketService call.
        if self._refresh_lock is None:
            self._refresh_lock = threading.Lock()

        # Auto-route an NT hash that landed in the password field. See
        # services/credential_routing.py for the rationale.
        from adscan_internal.services.credential_routing import (
            promote_credential_fields,
        )

        self.password, self.nt_hash, _, _ = promote_credential_fields(
            password=self.password, nt_hash=self.nt_hash
        )

    # -- Helpers -------------------------------------------------------------

    @property
    def registry_key(self) -> str:
        """Return the principal half of the epoch lookup key."""
        return self.principal_sid or self.username

    def _select_credential_for_asreq(self) -> tuple[str | None, str]:
        """Return ``(value, kind)`` for the most-restrictive-AD-friendly
        credential we can use for an AS-REQ.

        Order: password > AES key > NT hash.  Password is preferred because
        ``KerberosTicketService`` will derive AES keys on the fly and pre-auth
        succeeds even on KDCs with RC4 disabled.  AES key is next-best on
        AES-only KDCs.  NT hash is the legacy fallback and will fail when the
        KDC enforces AES-only — the caller learns this from the result.
        """
        if self.password:
            return self.password, "password"
        if self.aes_key:
            return self.aes_key, "aes_key"
        if self.nt_hash:
            return self.nt_hash, "nt_hash"
        return None, "none"

    def _ccache_mtime(self) -> float | None:
        """Return the on-disk mtime of the ccache, or ``None`` if absent."""
        path = self.ccache_path
        if not path:
            return None
        try:
            return os.path.getmtime(path)
        except OSError:
            return None

    def _is_stale(self, registry: CredentialRegistry) -> tuple[bool, str]:
        """Return ``(stale, reason)``.

        Layer 1 (timestamp): if the registry has an invalidation timestamp
        newer than the ccache's mtime, the ccache pre-dates the mutation and
        cannot contain its PAC effects.  This is the architecturally correct
        invariant — independent of when the context object was constructed.

        Layer 2 (epoch): fallback for the case where no ccache exists yet on
        disk (mtime is ``None``).  Compares snapshotted epoch against current.
        """
        ts = registry.last_invalidate_at_for(self.registry_key, self.auth_domain)
        mtime = self._ccache_mtime()
        if ts is not None and mtime is not None:
            if mtime < ts:
                return True, f"ccache_mtime={mtime:.3f}<invalidate_ts={ts:.3f}"
            # ccache is newer than the latest invalidation; layer 1 says fresh.
            # Do NOT consult the epoch fallback — it would cause a redundant
            # refresh when a stale-snapshot context binds against a fresh ccache.
            return False, "ccache_newer_than_last_invalidate"
        # Fallback: epoch comparison.
        current_epoch = registry.epoch_for(self.registry_key, self.auth_domain)
        if current_epoch > self.issued_at_epoch:
            return True, f"epoch={self.issued_at_epoch}<current={current_epoch}"
        return False, "fresh"

    # -- Refresh -------------------------------------------------------------

    async def refresh_if_stale(
        self,
        registry: CredentialRegistry | None = None,
        *,
        force: bool = False,
    ) -> bool:
        """Re-issue the TGT when the bound ccache is stale.

        Returns ``True`` when a refresh actually happened (the ccache on disk
        is now newer than before), ``False`` otherwise.  Errors during refresh
        are logged and swallowed: the caller will then try the bind with the
        stale ticket and report the eventual ``insufficientAccessRights`` /
        bind error normally.

        Staleness is determined by :meth:`_is_stale` (timestamp first, epoch
        fallback).  ``force=True`` bypasses both checks and refreshes
        unconditionally — used by the transport-level auto-retry in
        ``auth_retry.auth_aware_modify`` when a bind raises an access-denied
        error despite passing the staleness checks.
        """
        registry = registry or get_credential_registry()

        if not force:
            stale, reason = self._is_stale(registry)
            if not stale:
                return False
        else:
            reason = "force"

        # Hold the per-context lock so concurrent refreshes coalesce.
        if not self._refresh_lock.acquire(blocking=False):
            self._refresh_lock.acquire()
            self._refresh_lock.release()
            return False

        try:
            # Re-check after acquiring the lock (another caller may have
            # refreshed already in the interim).
            if not force:
                stale, reason = self._is_stale(registry)
                if not stale:
                    return False

            credential, kind = self._select_credential_for_asreq()
            if credential is None:
                print_warning(
                    "[cred-context] No credential material available to refresh TGT for "
                    f"{mark_sensitive(self.username, 'user')}@"
                    f"{mark_sensitive(self.auth_domain, 'domain')} — "
                    "bind will proceed with stale ticket and may fail."
                )
                return False
            if not self.workspace_dir:
                print_info_debug(
                    "[cred-context] workspace_dir missing; cannot persist refreshed ccache"
                )
                return False

            print_info_verbose(
                f"[cred-context] PAC stale ({reason}), refreshing TGT for "
                f"{mark_sensitive(self.username, 'user')}@"
                f"{mark_sensitive(self.auth_domain, 'domain')} via {kind}"
            )

            try:
                from adscan_internal.services.kerberos_ticket_service import (
                    KerberosTicketService,
                )

                service = KerberosTicketService()
                result = service.auto_generate_tgt(
                    username=self.username,
                    credential=credential,
                    domain=self.auth_domain,
                    workspace_dir=self.workspace_dir,
                    dc_ip=self.dc_ip,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_warning(
                    f"[cred-context] TGT refresh failed: {type(exc).__name__}: {exc}"
                )
                return False

            if not result.success or not result.ticket_path:
                print_warning(
                    "[cred-context] TGT refresh did not produce a ccache: "
                    f"{result.error_message or 'unknown error'}"
                )
                return False

            new_path = str(result.ticket_path)
            self.ccache_path = new_path
            # Bind to the freshly observed epoch — always advance, even on
            # ``force`` refreshes, so subsequent staleness checks reflect that
            # we are now post-mutation.
            self.issued_at_epoch = registry.epoch_for(
                self.registry_key, self.auth_domain
            )

            os.environ["KRB5CCNAME"] = new_path
            print_info_debug(
                "[cred-context] refreshed ccache "
                f"path={mark_sensitive(new_path, 'path')} "
                f"epoch={self.issued_at_epoch}"
            )
            return True
        finally:
            try:
                self._refresh_lock.release()
            except RuntimeError:
                pass

    # -- Construction helpers ------------------------------------------------

    @classmethod
    def for_executor(
        cls,
        *,
        username: str,
        auth_domain: str,
        principal_sid: str | None = None,
        password: str | None = None,
        nt_hash: str | None = None,
        aes_key: str | None = None,
        ccache_path: str | None = None,
        workspace_dir: str | None = None,
        dc_ip: str | None = None,
        registry: CredentialRegistry | None = None,
    ) -> "CredentialContext":
        """Build a context whose ``issued_at_epoch`` matches the registry's
        current state.

        Snapshotting the current epoch at construction is **only** used as a
        fallback when no ccache file exists on disk yet (e.g. first-ever bind
        on a synthetic context).  The primary staleness signal is the wall-
        clock comparison between the ccache's mtime and the registry's last
        invalidation timestamp — that comparison correctly flags stale
        tickets even when this context is built **after** the invalidation.
        """
        registry = registry or get_credential_registry()
        principal = (principal_sid or username or "").strip()
        ctx = cls(
            principal_sid=principal,
            username=username,
            auth_domain=auth_domain,
            password=password,
            nt_hash=nt_hash,
            aes_key=aes_key,
            ccache_path=ccache_path,
            workspace_dir=workspace_dir,
            dc_ip=dc_ip,
            issued_at_epoch=registry.epoch_for(principal, auth_domain),
        )
        return ctx
