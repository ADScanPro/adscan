"""PAL authentication seam — the Kerberos ccache-default side-effect.

The auth cryptography in ADscan is already pure-Python and cross-platform:
badldap -> badauth perform LDAP SASL sign+seal (``GSS_Wrap``/``GSS_Unwrap``/
``GSS_GetMIC``) themselves, reading the ccache from the ``kerberos-ccache`` URL
and ``KRB5CCNAME``; WinRM uses pypsrp -> pyspnego which auto-selects the native
SSPI backend on Windows and the GSSAPI backend on POSIX. The ONLY dependency on
the MIT-krb5 ``gssapi`` library in either path is a defensive side-effect that
points python-gssapi's *default* credential cache at the workspace ticket, for
any residual code that consults the UID default cache instead of ``KRB5CCNAME``.

This module localizes that side-effect so it is skipped cleanly on Windows
(where SSPI + ``KRB5CCNAME`` need no default-cache nudge) and behaves exactly as
before on POSIX. It imports the ``gssapi`` library ONLY inside the POSIX branch,
never at module top, so ``import adscan_core.pal.auth`` succeeds on Windows.
"""
from __future__ import annotations

from adscan_core.pal.platform import is_windows

__all__ = [
    "gssapi_default_ccache_supported",
    "set_gssapi_default_ccache",
    "swap_gssapi_default_ccache",
    "restore_gssapi_default_ccache",
]


def gssapi_default_ccache_supported() -> bool:
    """Report whether the gssapi default-ccache side-effect applies on this OS.

    POSIX uses the MIT-krb5 ``gssapi`` library, so the nudge is meaningful.
    Windows uses SSPI (and ``KRB5CCNAME`` for pyspnego's GSSAPI fallback where
    present), so there is no default-cache to nudge.
    """
    return not is_windows()


def set_gssapi_default_ccache(ccache_name: str) -> bool:
    """Point python-gssapi's default credential cache at ``ccache_name``.

    ``ccache_name`` is an already-formatted krb5 ccache name (e.g.
    ``FILE:/abs/path.ccache``); the caller formats it.

    POSIX attempts ``gssapi.raw.ext_krb5.krb5_ccache_name`` (the historical
    behavior) and returns True on success. Windows returns False immediately
    WITHOUT importing gssapi. Never raises — a failure returns False and the
    caller falls back to ``KRB5CCNAME`` alone.

    Returns:
        True if the default ccache was applied, False otherwise (including on
        Windows and on any error).
    """
    if is_windows():
        return False
    try:
        from gssapi.raw.ext_krb5 import (  # pylint: disable=no-name-in-module
            krb5_ccache_name,
        )

        krb5_ccache_name(ccache_name.encode("utf-8"))
        return True
    except Exception:  # noqa: BLE001 - optional runtime dependency; never fatal
        return False


def swap_gssapi_default_ccache(ccache_name: str) -> tuple[bool, bytes | None]:
    """Set the gssapi default ccache and return the PREVIOUS value for restore.

    Used by callers that must restore the thread's prior default ccache after a
    scoped operation (e.g. the WinRM ccache context manager). POSIX applies the
    new ccache and returns ``(True, previous_bytes_or_None)``; Windows returns
    ``(False, None)`` without importing gssapi. Never raises.

    Args:
        ccache_name: Already-formatted krb5 ccache name (e.g. ``FILE:/abs.ccache``).

    Returns:
        ``(applied, previous)`` — ``applied`` True iff the swap happened;
        ``previous`` is the prior default-ccache bytes to hand back to
        :func:`restore_gssapi_default_ccache`, or None.
    """
    if is_windows():
        return (False, None)
    try:
        from gssapi.raw.ext_krb5 import (  # pylint: disable=no-name-in-module
            krb5_ccache_name,
        )

        previous = krb5_ccache_name(ccache_name.encode("utf-8"))
        return (True, previous)
    except Exception:  # noqa: BLE001 - optional runtime dependency; never fatal
        return (False, None)


def restore_gssapi_default_ccache(previous: bytes | None) -> None:
    """Restore a default ccache captured by :func:`swap_gssapi_default_ccache`.

    POSIX re-applies ``previous`` via gssapi; Windows and a ``None`` previous are
    no-ops. Never raises.
    """
    if is_windows() or previous is None:
        return
    try:
        from gssapi.raw.ext_krb5 import (  # pylint: disable=no-name-in-module
            krb5_ccache_name,
        )

        krb5_ccache_name(previous)
    except Exception:  # noqa: BLE001 - optional runtime dependency; never fatal
        return
