"""Centralised Kerberos error recovery for the entire native stack.

Importing this module monkey-patches ``kerbad.aioclient.AIOKerberosClient.with_clock_skew``
so that **every** kerbad-driven flow — kerberos_transport, badauth (LDAP / SMB / RPC),
badldap, aiosmb — transparently recovers from:

* ``KRB_AP_ERR_SKEW``        — clock drift (already covered by kerbad upstream)
* ``KRB_AP_ERR_TKT_EXPIRED`` — TGT/ticket lifetime exhausted mid-run
* ``KRB_AP_ERR_TKT_NYV``     — ticket not yet valid (boundary skew variant)
* ``KDC_ERR_TGT_REVOKED``    — TGT revoked / forced renewal

When the wrapped function is anything other than ``get_TGT`` itself and the
client's ``KerberosCredential`` carries a renewable secret (password, NT hash,
AES key, certificate / PKINIT material), the patched wrapper re-issues an
AS-REQ via ``client.get_TGT(...)`` and retries the original call **once**.
Cred-only-via-CCACHE situations propagate the original error untouched —
without the secret, no fresh TGT is possible from this layer.

Single source of truth: every callsite that uses ``client.with_clock_skew(...)``
inherits the recovery transparently, including the badauth path that performs
``self.kc.with_clock_skew(self.kc.get_TGS, spn)`` after a stale CCACHE TGT.

This module is import-once, idempotent, and never imports anything from
``adscan_internal`` to keep the dependency direction clean.

Patch A — global realm skew cache + ``AIOKerberosClient.__init__`` pre-seeding
    ``_REALM_SKEW_CACHE`` (keyed by uppercase realm) is populated whenever
    kerbad's ``with_clock_skew`` wrapper successfully learns a skew (from a
    KRB-ERROR stime).  ``kerbad.aioclient.AIOKerberosClient.__init__`` is
    patched to read the cache at construction time so every fresh ``kc``
    created for the same realm starts with the correct offset.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


_PATCH_MARKER = "_adscan_recovery_patched"

# ---------------------------------------------------------------------------
# Patch A — module-level realm skew cache
# ---------------------------------------------------------------------------
# Plain dict: asyncio is single-threaded within an event loop so no lock
# is needed for dict reads and writes in coroutines.  Background threads are
# not expected to write here.
_REALM_SKEW_CACHE: dict[str, datetime.timedelta] = {}

# ---------------------------------------------------------------------------
# Expiry auto-renewal — shell-aware re-mint reminters (dependency inversion)
# ---------------------------------------------------------------------------
# A reminter is a zero-arg callback returning a path to a FRESH ccache (or
# None when it could not re-mint). It is registered by a higher layer
# (the transport, which DOES hold the principal secret via CredentialContext)
# and consulted here when a mid-bind KRB_AP_ERR_TKT_EXPIRED hits a credential
# that is ccache-only (no renewable secret at this layer). Same single-loop
# rationale as _REALM_SKEW_CACHE: asyncio is single-threaded within an event
# loop, so plain dict reads/writes are safe.
#
# Layering: this module MUST NOT import anything from adscan_internal. The
# reminter is injected as an opaque callback so the dependency direction stays
# clean (the transport depends on us, never the reverse).
_REALM_EXPIRY_REMINTERS: dict[str, "Callable[[], str | None]"] = {}

# Re-entrancy guard: set while a reminter callback runs so a reminter that
# triggers its own Kerberos primitive (e.g. its re-mint issues a TGS) cannot
# recurse back into expiry auto-renewal.
_REMINTER_RUNNING = False

# ---------------------------------------------------------------------------
# PKINIT physical clock-resync backstop (dependency inversion)
# ---------------------------------------------------------------------------
# Reactive last line of defence for PKINIT: kerbad's per-request ``clock_skew``
# offset is IN-MEMORY only -- it never touches the system clock. That is correct
# and sufficient for AS/TGS (``KRB_AP_ERR_SKEW``, 0x25), but INSUFFICIENT for
# PKINIT: the KDC validates the certificate's notBefore/notAfter window AND the
# CMS-signed ``PKAuthenticator`` against the DC's REAL time, which only a
# PHYSICAL clock step fixes. A host clock that drifted far enough (observed ~7h
# behind) makes PKINIT fail ``KDC_ERR_CLIENT_NOT_TRUSTED`` (0x3E) no matter how
# we adjust the in-memory offset.
#
# A proactive guard (``dc_time.ensure_clock_synced_fresh``) physically steps the
# clock at the known PKINIT/attack-path/DCSync entry points. This callback is the
# REACTIVE BACKSTOP so a MISSED or future PKINIT path self-heals at the transport
# layer: on a 0x3E with a PKINIT cert credential in play, we invoke the
# registered resync callback (which physically steps the clock) and retry once.
#
# The callback takes a realm/domain and returns True iff it physically resynced
# (so a retry is worthwhile). It is injected by a higher layer (ADscan, which
# owns the shell + the host-helper clock step). Layering: this module MUST NOT
# import anything from adscan_internal -- the callback is an opaque ``Callable``
# so the dependency direction stays clean. Same single-loop rationale as
# ``_REALM_SKEW_CACHE``: asyncio is single-threaded within an event loop, so a
# plain module global is safe.
_CLOCK_RESYNC_CALLBACK: "Callable[[str], bool] | None" = None

# Re-entrancy guard: set while the resync callback runs so a resync that itself
# triggers a Kerberos primitive (the DC-time read uses SMB Negotiate, not
# Kerberos, but defence in depth) cannot recurse back into the 0x3E backstop.
_CLOCK_RESYNC_RUNNING = False


def register_clock_resync_callback(callback: "Callable[[str], bool]") -> None:
    """Register the PKINIT physical clock-resync backstop callback.

    Args:
        callback: Takes a realm/domain string, physically resyncs the host
            clock against that domain's DC, and returns ``True`` iff a physical
            step occurred (so retrying the failed PKINIT primitive is
            worthwhile). A return of ``False`` (already in tolerance, no DC IP,
            sync failed) leaves the existing behavior untouched.

    Single callback for the whole session (one event loop, one host clock).
    Re-registration replaces the previous callback.
    """
    global _CLOCK_RESYNC_CALLBACK
    _CLOCK_RESYNC_CALLBACK = callback


def unregister_clock_resync_callback() -> None:
    """Remove the registered clock-resync callback (no-op when absent)."""
    global _CLOCK_RESYNC_CALLBACK
    _CLOCK_RESYNC_CALLBACK = None


def _try_clock_resync(credential: Any) -> bool:
    """Invoke the registered physical clock-resync callback for *credential*'s realm.

    Returns ``True`` only when a callback is registered, a realm is resolvable,
    and the callback reports it physically stepped the clock (so a single retry
    of the failed PKINIT primitive is worthwhile). Re-entrancy guarded so a
    resync that itself triggers Kerberos cannot recurse. Best-effort: a broken
    callback never masks the original Kerberos error.
    """
    global _CLOCK_RESYNC_RUNNING
    if _CLOCK_RESYNC_RUNNING:
        return False
    callback = _CLOCK_RESYNC_CALLBACK
    if callback is None:
        return False
    realm = (getattr(credential, "domain", None) or "").strip()
    if not realm:
        return False
    _CLOCK_RESYNC_RUNNING = True
    try:
        stepped = bool(callback(realm))
    except Exception as exc:  # noqa: BLE001 -- a broken backstop must not mask the original error
        logger.warning("PKINIT clock-resync backstop raised for realm %s: %r", realm, exc)
        return False
    finally:
        _CLOCK_RESYNC_RUNNING = False
    if stepped:
        logger.warning(
            "PKINIT failed CLIENT_NOT_TRUSTED with a cert credential; physically "
            "resynced the host clock for realm %s and retrying once.",
            realm,
        )
    else:
        logger.debug(
            "PKINIT CLIENT_NOT_TRUSTED backstop: resync callback reported no "
            "physical step for realm %s; propagating.",
            realm,
        )
    return stepped


def register_expiry_reminter(realm: str, callback: "Callable[[], str | None]") -> None:
    """Register a re-mint callback for *realm* (uppercased).

    The callback takes no arguments and returns the path to a freshly minted
    ccache for the principal, or ``None`` when it could not re-mint. The
    transport that registers it owns deregistration (always in a ``finally``)
    so a reminter never leaks across operations or principals.
    """
    if not realm:
        return
    _REALM_EXPIRY_REMINTERS[realm.upper()] = callback


def unregister_expiry_reminter(realm: str) -> None:
    """Remove any reminter registered for *realm* (no-op when absent)."""
    if not realm:
        return
    _REALM_EXPIRY_REMINTERS.pop(realm.upper(), None)


def _credential_can_refresh_tgt(credential: Any) -> bool:
    """Return True when the credential carries a secret usable for a fresh AS-REQ."""
    if credential is None:
        return False
    secret_attrs = (
        "password",
        "nt_hash",
        "kerberos_key_aes_256",
        "kerberos_key_aes_128",
        "kerberos_key_rc4",
        "kerberos_key_des3",
        "kerberos_key_des",
        "certificate",
    )
    for attr in secret_attrs:
        if getattr(credential, attr, None):
            return True
    return False


def _is_recoverable_ticket_error(exc: BaseException, error_code_cls: Any) -> bool:
    """True if ``exc`` is a Kerberos ticket-expired/revoked/not-yet-valid error."""
    code = getattr(exc, "errorcode", None)
    if code is None:
        return False
    candidates = []
    for name in ("KRB_AP_ERR_TKT_EXPIRED", "KRB_AP_ERR_TKT_NYV", "KDC_ERR_TGT_REVOKED"):
        value = getattr(error_code_cls, name, None)
        if value is not None:
            candidates.append(value)
    return code in candidates


def install() -> None:
    """Install all recovery patches.  Idempotent: re-imports do not stack patches."""
    _install_kerbad_with_clock_skew()
    _install_patch_a_init()
    _install_sync_kerbad_patches()


# ---------------------------------------------------------------------------
# Existing patch — kerbad with_clock_skew + ticket-expired recovery
# ---------------------------------------------------------------------------


def _try_reminter_refresh(client: Any) -> bool:
    """Run a registered reminter for the client's realm and reload its ccache.

    Returns ``True`` when a reminter produced a fresh ccache that was reloaded
    into ``client.credential.ccache`` (and ``client.kerberos_TGT`` was reset so
    the retried primitive re-reads it); ``False`` when there is no reminter, it
    returned ``None``, or reloading failed. Re-entrancy guarded so a reminter
    that triggers its own Kerberos primitive cannot recurse.
    """
    global _REMINTER_RUNNING
    if _REMINTER_RUNNING:
        return False
    credential = getattr(client, "credential", None)
    realm = (getattr(credential, "domain", None) or "").upper()
    if not realm:
        return False
    reminter = _REALM_EXPIRY_REMINTERS.get(realm)
    if reminter is None:
        return False
    _REMINTER_RUNNING = True
    try:
        fresh_path = reminter()
    except Exception as exc:  # noqa: BLE001 — a broken reminter must not mask the original error
        logger.warning("Kerberos expiry reminter raised for realm %s: %r", realm, exc)
        return False
    finally:
        _REMINTER_RUNNING = False
    if not fresh_path:
        logger.debug("Kerberos expiry reminter for realm %s returned no ccache.", realm)
        return False
    try:
        from kerbad.common.ccache import CCACHE  # noqa: PLC0415

        fresh_ccache = CCACHE.from_file(fresh_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Kerberos expiry reminter produced ccache %s but reload failed: %r",
            fresh_path,
            exc,
        )
        return False
    # Reload the fresh ccache into BOTH the credential AND the client's OWN
    # ``self.ccache``. get_TGS -> tgs_from_ccache and tgt_from_ccache read
    # ``client.ccache`` (aioclient captures it ONCE at __init__, a SEPARATE
    # reference from ``credential.ccache`` — see aioclient.py:46-48). Setting only
    # ``credential.ccache`` left the retried get_TGS reading the stale, expired
    # ticket, so it re-raised TKT_EXPIRED on every retry (the observed loop).
    # Clear the cached TGT/TGS so the next primitive re-derives them from the
    # fresh ccache.
    credential.ccache = fresh_ccache
    client.ccache = fresh_ccache
    client.kerberos_TGT = None
    client.kerberos_TGT_encpart = None
    client.kerberos_TGS = None
    logger.warning(
        "Kerberos ticket expired (ccache-only credential); re-minted via reminter "
        "for realm %s and retrying.",
        realm,
    )
    return True


def _install_kerbad_with_clock_skew() -> None:
    try:
        from kerbad.aioclient import AIOKerberosClient  # noqa: PLC0415
        from kerbad.protocol.errors import KerberosError, KerberosErrorCode  # noqa: PLC0415
    except ImportError:
        return

    if getattr(AIOKerberosClient.with_clock_skew, _PATCH_MARKER, False):
        return

    original_with_clock_skew = AIOKerberosClient.with_clock_skew

    async def _refresh_tgt(client: AIOKerberosClient) -> None:
        """Re-issue an AS-REQ in place using the credential's renewable secret."""
        override_etypes = (
            list(getattr(client.credential, "override_etypes", []) or []) or None
        )
        # Use the original, un-patched ``with_clock_skew`` so a refresh does not
        # recurse into our patched wrapper while it is itself recovering.
        await original_with_clock_skew(
            client, client.get_TGT, override_etype=override_etypes
        )

    async def with_clock_skew_recovery(
        self: AIOKerberosClient,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        try:
            result = await original_with_clock_skew(self, func, *args, **kwargs)
            # Patch A: persist any skew kerbad just learned to the realm cache.
            # kerbad sets self.clock_skew when it detects KRB_AP_ERR_SKEW;
            # we mirror it to _REALM_SKEW_CACHE so fresh kc instances
            # start with the correct offset.
            _sync_skew_to_cache(self)
            return result
        except KerberosError as exc:
            # Mirror skew even on failure (kerbad may have set it before re-raising).
            _sync_skew_to_cache(self)
            # PKINIT physical clock-resync backstop (async path). A PKINIT cert
            # credential that flows through the async client surfaces a stale
            # signed ctime / out-of-window cert as KDC_ERR_CLIENT_NOT_TRUSTED
            # (0x3E), NOT KRB_AP_ERR_SKEW — and the in-memory offset cannot fix
            # it (the KDC validates against its REAL time). Trigger a PHYSICAL
            # host-clock resync and retry once when it stepped. PKINIT normally
            # runs on the SYNC client, but this keeps any future async PKINIT
            # path self-healing too.
            _cred = getattr(self, "credential", None)
            if (
                getattr(exc, "errorcode", None)
                == KerberosErrorCode.KDC_ERR_CLIENT_NOT_TRUSTED
                and getattr(_cred, "certificate", None) is not None
                and _try_clock_resync(_cred)
            ):
                result = await original_with_clock_skew(self, func, *args, **kwargs)
                _sync_skew_to_cache(self)
                return result
            if not _is_recoverable_ticket_error(exc, KerberosErrorCode):
                raise
            # Avoid recursion: if we were already inside get_TGT, a fresh TGT
            # won't fix anything (the AS-REQ itself returned the error).
            if getattr(func, "__name__", "") == "get_TGT":
                raise
            if not _credential_can_refresh_tgt(getattr(self, "credential", None)):
                # Ccache-only credential (LDAP/SMB bind path): this layer has no
                # secret to re-issue an AS-REQ, but a higher layer may have
                # registered a shell-aware reminter that DOES. Consult it; on a
                # fresh ccache, reload it and retry the original primitive once.
                if _try_reminter_refresh(self):
                    result = await original_with_clock_skew(self, func, *args, **kwargs)
                    _sync_skew_to_cache(self)
                    return result
                logger.debug(
                    "Kerberos ticket expired but credential has no renewable "
                    "secret (ccache-only) and no reminter is registered for the "
                    "realm; propagating."
                )
                raise
            # Apply clock_skew from the KRB_ERROR's stime before refreshing.
            # TKT_EXPIRED is server-side, but if the local clock has drifted
            # since the original TGT was issued, the refresh AS-REQ would
            # otherwise carry skewed timestamps and fail with KRB_AP_ERR_SKEW
            # on the very next call. Cost is zero — stime is already in the
            # error message we just received.
            try:
                server_time = exc.krb_err_msg["stime"]
                local_time = datetime.datetime.now(datetime.timezone.utc)
                self.clock_skew = server_time - local_time
                _sync_skew_to_cache(self)
            except Exception:  # noqa: BLE001 — best-effort sync, never fatal
                pass
            logger.warning(
                "Kerberos ticket expired (%s); refreshing TGT and retrying %s.",
                getattr(exc, "errorcode", "?"),
                getattr(func, "__name__", repr(func)),
            )
            await _refresh_tgt(self)
            result = await original_with_clock_skew(self, func, *args, **kwargs)
            _sync_skew_to_cache(self)
            return result

    setattr(with_clock_skew_recovery, _PATCH_MARKER, True)
    AIOKerberosClient.with_clock_skew = with_clock_skew_recovery

    # Auto-route every Kerberos primitive through with_clock_skew so callers
    # cannot bypass clock-skew + ticket-expired recovery by accident. Any future
    # `await client.S4U2self(...)` style call inherits the same recovery as
    # explicit `client.with_clock_skew(client.S4U2self, ...)`. Idempotent.
    _AUTO_WRAP_METHODS = (
        "get_TGT",
        "get_TGS",
        "S4U2self",
        "S4U2proxy",
        "getST",
        "U2U",
        "get_referral_ticket",
    )
    for _method_name in _AUTO_WRAP_METHODS:
        original = getattr(AIOKerberosClient, _method_name, None)
        if original is None or getattr(original, _PATCH_MARKER, False):
            continue

        def _make_wrapper(method_name: str, original_func: Callable[..., Any]):
            async def _auto_clock_skew_wrapper(self, *args: Any, **kwargs: Any) -> Any:
                return await self.with_clock_skew(original_func, self, *args, **kwargs)

            setattr(_auto_clock_skew_wrapper, _PATCH_MARKER, True)
            _auto_clock_skew_wrapper.__name__ = method_name
            _auto_clock_skew_wrapper.__qualname__ = f"AIOKerberosClient.{method_name}"
            return _auto_clock_skew_wrapper

        setattr(AIOKerberosClient, _method_name, _make_wrapper(_method_name, original))


def _sync_skew_to_cache(client: Any) -> None:
    """Write *client*.clock_skew into _REALM_SKEW_CACHE if non-None."""
    skew = getattr(client, "clock_skew", None)
    if skew is None:
        return
    try:
        realm = client.credential.domain.upper()
        if realm:
            _REALM_SKEW_CACHE[realm] = skew
            logger.debug("Realm skew cache updated: %s → %s", realm, skew)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Patch A — kerbad AIOKerberosClient.__init__ pre-seeding from realm cache
# ---------------------------------------------------------------------------


def _install_patch_a_init() -> None:
    """Patch kerbad AIOKerberosClient.__init__ to pre-seed clock_skew from cache."""
    try:
        from kerbad.aioclient import AIOKerberosClient  # noqa: PLC0415
    except ImportError:
        return

    if getattr(AIOKerberosClient.__init__, _PATCH_MARKER, False):
        return

    original_init = AIOKerberosClient.__init__

    def patched_init(self, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        # If we already know the clock skew for this realm, pre-seed it so
        # the very first Kerberos request uses the correct timestamp without
        # needing a KRB-ERROR round-trip.
        try:
            realm = (getattr(self.credential, "domain", None) or "").upper()
            if realm and realm in _REALM_SKEW_CACHE:
                self.clock_skew = _REALM_SKEW_CACHE[realm]
                logger.debug(
                    "Pre-seeded clock_skew=%s for realm %s from cache",
                    self.clock_skew,
                    realm,
                )
        except Exception:  # noqa: BLE001
            pass

    setattr(patched_init, _PATCH_MARKER, True)
    AIOKerberosClient.__init__ = patched_init


# ---------------------------------------------------------------------------
# Sync client patches — kerbad KerbrosClient (used by PKINIT / shadow creds)
# ---------------------------------------------------------------------------


def _install_sync_kerbad_patches() -> None:
    """Mirror the skew recovery onto the SYNC ``KerbrosClient``.

    Shadow-credentials / PKINIT build the SYNC ``kerbad.client.KerbrosClient``
    via ``get_client_blocking()`` — which the async-only patches above never
    touch. Without this, the sync client starts with ``clock_skew=None`` and
    stamps the PKINIT PKAuthenticator ``ctime`` on the un-skewed local clock; a
    skewed PKINIT AS-REQ is rejected by the KDC with
    ``KDC_ERR_CLIENT_NOT_TRUSTED (0x3E)`` (PKINIT reports a stale *signed*
    timestamp as a client-trust failure, NOT ``KRB_AP_ERR_SKEW (0x25)``), and the
    stock sync ``with_clock_skew`` only recovers from ``0x25``. Two fixes:

    1. ``__init__`` pre-seed from ``_REALM_SKEW_CACHE`` (same as Patch A on the
       async client) — the realm skew the async transports already learned makes
       the very first PKINIT request correct, no round-trip wasted.
    2. ``with_clock_skew`` also recovers from ``0x3E`` when a PKINIT certificate
       credential is in play: the KRB-ERROR still carries the server ``stime``,
       so we learn the real skew, mirror it to the cache, and retry once.
    """
    try:
        from kerbad.client import KerbrosClient  # noqa: PLC0415
        from kerbad.protocol.errors import (  # noqa: PLC0415
            KerberosError,
            KerberosErrorCode,
        )
    except ImportError:
        return

    if not getattr(KerbrosClient.__init__, _PATCH_MARKER, False):
        original_init = KerbrosClient.__init__

        def patched_sync_init(self, *args: Any, **kwargs: Any) -> None:
            original_init(self, *args, **kwargs)
            try:
                realm = (getattr(self.credential, "domain", None) or "").upper()
                if realm and realm in _REALM_SKEW_CACHE:
                    self.clock_skew = _REALM_SKEW_CACHE[realm]
                    logger.debug(
                        "Pre-seeded sync clock_skew=%s for realm %s from cache",
                        self.clock_skew,
                        realm,
                    )
            except Exception:  # noqa: BLE001
                pass

        setattr(patched_sync_init, _PATCH_MARKER, True)
        KerbrosClient.__init__ = patched_sync_init

    if not getattr(KerbrosClient.with_clock_skew, _PATCH_MARKER, False):

        def sync_with_clock_skew(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
            try:
                result = func(*args, **kwargs)
                _sync_skew_to_cache(self)
                return result
            except KerberosError as exc:
                code = getattr(exc, "errorcode", None)
                is_skew = code == KerberosErrorCode.KRB_AP_ERR_SKEW
                # PKINIT (cert credential) surfaces a stale signed ctime as
                # CLIENT_NOT_TRUSTED, not SKEW.
                is_pkinit_trust = (
                    code == KerberosErrorCode.KDC_ERR_CLIENT_NOT_TRUSTED
                    and getattr(getattr(self, "credential", None), "certificate", None)
                    is not None
                )
                if not (is_skew or is_pkinit_trust):
                    raise
                # PKINIT backstop: the in-memory ``clock_skew`` offset does NOT
                # touch the system clock and is INSUFFICIENT for PKINIT — the KDC
                # validates the cert window + the CMS-signed PKAuthenticator
                # against its REAL time. Trigger a PHYSICAL host-clock resync (via
                # the injected backstop callback) and, when it stepped, retry once.
                # The physical step makes the cert window + signed authenticator
                # valid; the in-memory offset path below would NOT.
                if is_pkinit_trust and _try_clock_resync(getattr(self, "credential", None)):
                    result = func(*args, **kwargs)
                    _sync_skew_to_cache(self)
                    return result
                # KRB_AP_ERR_SKEW (and the no-resync PKINIT fallback): the
                # in-memory offset recovery is correct + sufficient for AS/TGS.
                try:
                    server_time = exc.krb_err_msg["stime"]
                    local_time = datetime.datetime.now(datetime.timezone.utc)
                    self.clock_skew = server_time - local_time
                except Exception:  # noqa: BLE001
                    raise exc
                logger.warning(
                    "Clock skew detected on sync client (code=%s); adjusting by %s "
                    "and retrying once.",
                    code,
                    self.clock_skew,
                )
                _sync_skew_to_cache(self)
                result = func(*args, **kwargs)
                _sync_skew_to_cache(self)
                return result

        setattr(sync_with_clock_skew, _PATCH_MARKER, True)
        KerbrosClient.with_clock_skew = sync_with_clock_skew


install()
