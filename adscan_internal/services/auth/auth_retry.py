"""Transport-level auto-retry on access-denied bind / modify errors.

The credential context's wall-clock + epoch staleness checks
(``CredentialContext.refresh_if_stale``) cover **known** invalidations.  But
some staleness signals do not reach the registry — for example an out-of-band
GPO refresh, a privilege change made outside ADscan, or an edge case where the
registry timestamp barely loses to the ccache mtime.  When that happens the
bind succeeds but the modify returns ``insufficientAccessRights``.

This module wraps an LDAP-modify-style operation with a defence-in-depth
auto-retry:

    operation()
       │
       └── access denied? ───► force-refresh TGT, retry once
                                  │
                                  └── still denied? ───► (optionally) NTLM
                                                            fallback if the
                                                            operator allowed
                                                            it and the DC
                                                            speaks NTLM
                                                            (capability cache).

Retry budget: one per layer.  No loops.  The original exception is preserved
and re-raised when every recovery path fails — the first error is the most
informative for the operator.
"""

from __future__ import annotations

import dataclasses as _dc
from typing import Any, Awaitable, Callable, TypeVar

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_info_verbose,
    print_warning,
)
from adscan_core.rich_output import print_exception

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Access-denied detection — closed catalogue of markers we know the badldap /
# minikerberos / kerbad / aiosmb stack can emit.  Centralised so a new vector
# only needs one update.
# ---------------------------------------------------------------------------

_ACCESS_DENIED_MARKERS: tuple[str, ...] = (
    "insufficientaccessrights",
    "insufficient access rights",
    "insufficient_access",
    "ldap_insufficient_access",
    "error_access_denied",
    "access_denied",
    "0x80072098",          # ADS_AUTHENTICATION (insufficient rights)
    "status_access_denied",
    "0xc0000022",          # NT STATUS_ACCESS_DENIED
)


def is_access_denied_error(exc_or_msg: Any) -> bool:
    """Return ``True`` when the value indicates an AD access-denied condition.

    Accepts an exception, a string, or any object whose ``str()`` representation
    contains a known marker.  Case-insensitive.
    """
    if exc_or_msg is None:
        return False
    text = str(exc_or_msg).casefold()
    return any(marker in text for marker in _ACCESS_DENIED_MARKERS)


# ---------------------------------------------------------------------------
# Wrapper
# ---------------------------------------------------------------------------


async def auth_aware_modify(
    *,
    operation: Callable[[], Awaitable[T]],
    credential_context: Any | None,
    config: Any | None = None,
    ntlm_fallback_allowed: bool = True,
    sensitive_op_label: str = "ldap_modify",
) -> T:
    """Run ``operation`` with automatic auth-recovery on access-denied.

    Args:
        operation: Zero-arg async callable that performs the LDAP modify.  The
            callable is responsible for opening a fresh connection internally
            so a retry sees the new ccache (the credential context updates its
            ``ccache_path`` in place when refresh succeeds).
        credential_context: Optional :class:`CredentialContext`.  When set, a
            ``refresh_if_stale(force=True)`` is performed before the retry.
        config: Optional :class:`ADscanLDAPConfig` snapshot.  Used by the NTLM
            fallback layer to construct an NTLM-bound copy.  The caller's
            ``operation`` closure must read from this same config object for
            the fallback to take effect — pass ``operation`` as a closure that
            captures ``config`` and use ``config.use_kerberos = False`` when
            triggering the NTLM retry, or rebuild the connection in ``operation``
            from the live ``config``.
        ntlm_fallback_allowed: Operator-controlled gate.  When ``False`` the
            NTLM layer is skipped even if the DC supports it.
        sensitive_op_label: Stable string used in debug logs.

    Returns:
        Whatever ``operation`` returns on its first successful attempt.

    Raises:
        Exception: The **first** exception from ``operation`` when no recovery
            path succeeds.  Recovery-attempt exceptions are logged and
            discarded so the operator sees the canonical auth error.
    """
    # ---- Attempt 1 ----------------------------------------------------------
    first_exc: Exception | None = None
    try:
        return await operation()
    except Exception as exc:  # noqa: BLE001
        first_exc = exc
        if not is_access_denied_error(exc):
            raise
        print_info_debug(
            f"[auth-retry] {sensitive_op_label}: access denied "
            f"({type(exc).__name__}); trying TGT refresh + retry"
        )

    # ---- Attempt 2: force TGT refresh + retry ------------------------------
    if credential_context is not None:
        try:
            refreshed = await credential_context.refresh_if_stale(force=True)
            if refreshed:
                print_info_verbose(
                    "[auth-retry] forced TGT refresh succeeded; retrying "
                    f"{sensitive_op_label} for "
                    f"{mark_sensitive(getattr(credential_context, 'username', ''), 'user')}"
                )
            try:
                return await operation()
            except Exception as exc:  # noqa: BLE001
                if not is_access_denied_error(exc):
                    # A different error after refresh — surface it directly,
                    # it is more relevant than the original access-denied.
                    raise
                print_info_debug(
                    f"[auth-retry] still access-denied after force-refresh "
                    f"({type(exc).__name__}); considering NTLM fallback"
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[auth-retry] force-refresh raised {type(exc).__name__}: {exc}"
            )

    # ---- Attempt 3: NTLM fallback (capability-gated, operator-gated) -------
    if (
        ntlm_fallback_allowed
        and config is not None
        and getattr(config, "use_kerberos", False)
    ):
        try:
            from adscan_internal.services.auth.ntlm_capability import (
                get_ntlm_capability_cache,
            )

            cache = get_ntlm_capability_cache()
            realm = str(getattr(config, "domain", "") or "").strip()
            dc_host = str(
                getattr(config, "kerberos_target_hostname", "")
                or getattr(config, "dc_ip", "")
                or ""
            ).strip()
            available = cache.is_available(realm, dc_host)
            if available is False:
                print_info_debug(
                    "[auth-retry] NTLM marked unavailable in capability cache; skipping fallback"
                )
            else:
                # Build an NTLM-bound copy of the config.  The caller-supplied
                # ``operation`` is expected to consult the live ``config``
                # object to pick up this change.
                try:
                    ntlm_config = _dc.replace(
                        config,
                        use_kerberos=False,
                        ccache_path=None,
                        credential_context=None,
                    )
                except Exception:  # noqa: BLE001
                    ntlm_config = None

                if ntlm_config is not None and getattr(ntlm_config, "password", None):
                    print_info_verbose(
                        f"[auth-retry] attempting NTLM fallback for {sensitive_op_label} "
                        f"against {mark_sensitive(dc_host, 'host')}"
                    )
                    # Mutate caller's config in place so the closure sees it.
                    # (We can't rebuild the closure here.)
                    try:
                        config.use_kerberos = False
                        # Probe success: if the operation returns, NTLM works.
                        result = await operation()
                        cache.mark_available(realm, dc_host)
                        return result
                    except Exception as exc:  # noqa: BLE001
                        if _is_ntlm_blocked(exc):
                            cache.mark_unavailable(
                                realm, dc_host, reason=str(exc)[:120]
                            )
                            print_info_debug(
                                "[auth-retry] NTLM fallback rejected by DC policy; "
                                "marking realm as NTLM-unavailable"
                            )
                        else:
                            print_info_debug(
                                f"[auth-retry] NTLM fallback failed: "
                                f"{type(exc).__name__}: {exc}"
                            )
                else:
                    print_info_debug(
                        "[auth-retry] NTLM fallback unavailable: no password / config"
                    )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning(
                f"[auth-retry] NTLM fallback layer raised {type(exc).__name__}: {exc}"
            )

    # ---- All recovery paths exhausted — re-raise the original error -------
    assert first_exc is not None
    raise first_exc


_NTLM_BLOCKED_MARKERS: tuple[str, ...] = (
    "status_ntlm_blocked",
    "0xc0000418",          # STATUS_AUTHENTICATION_FIREWALL_FAILED
    "ntlm_disabled",
    "ntlm is disabled",
    "ntlm_blocked",
    "kdc_err_preauth_failed",  # explicit NTLM-relay-style block
)


def _is_ntlm_blocked(exc_or_msg: Any) -> bool:
    """Return ``True`` when the error indicates the DC refuses NTLM by policy."""
    text = str(exc_or_msg).casefold()
    return any(marker in text for marker in _NTLM_BLOCKED_MARKERS)
