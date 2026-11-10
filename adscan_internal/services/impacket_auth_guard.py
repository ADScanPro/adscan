"""Put impacket's two secret-sending functions behind the sign-in lockout guard.

ADscan still drives a few operations through impacket (MSSQL over TDS, the
GKDI call that decrypts LAPS, two CVE probes). impacket builds every NTLM
AUTHENTICATE in ``impacket.ntlm.getNTLMSSPType3`` and every Kerberos AS exchange
in ``impacket.krb5.kerberosv5.getKerberosTGT``, whatever the transport, and its
modules look both up as module attributes at call time. Wrapping those two is
therefore the impacket equivalent of the kerbad ``get_TGT`` patch in
``_kerberos_recovery``:

* ``getKerberosTGT`` is an AS exchange: the guard checks it before it is sent
  and records the classified outcome (``auth_outcome.classify_kerberos_as``;
  only ``KDC_ERR_PREAUTH_FAILED`` counts).
* ``getNTLMSSPType3`` only BUILDS the AUTHENTICATE; the verdict arrives later
  in a transport-specific reply (an SMB status, an RPC fault, a TDS login
  reply) that this layer cannot see. So it is check-only: a secret the domain
  already rejected, an unusable account, a principal at its budget, or an empty
  secret is refused before the message is built. The transport seam that can
  read the reply records it (MSSQL: ``ImpacketMSSQLBackend._authenticate``).

The import is lazy, because importing impacket's Kerberos module costs a third
of a second: every module that drives an impacket sign-in calls
:func:`install_impacket_auth_guard` first (idempotent, a flag check after the
first call), and a structural test fails when a new one does not.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_exception

__all__ = ["install_impacket_auth_guard"]

_MARKER = "_adscan_auth_guard"
_LOCK = threading.Lock()
_INSTALLED = False


def _as_text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return str(value or "")


def _principal_name(client_name: Any) -> str:
    components = getattr(client_name, "components", None)
    if components:
        return str(components[0])
    return str(client_name or "").split("@", 1)[0]


def _secret_from(password: Any, nthash: Any, aes_key: Any) -> str:
    for value in (password, nthash, aes_key):
        text = _as_text(value)
        if text:
            return text
    return ""


def _impacket_error_code(exc: BaseException) -> "int | None":
    """The numeric Kerberos error code of an impacket ``KerberosError``, or ``None``."""
    try:
        return int(exc.getErrorCode())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - not a Kerberos error (socket, timeout)
        return None


def _wrap_get_kerberos_tgt(original: Callable[..., Any]) -> Callable[..., Any]:
    from adscan_core import auth_attempt_guard  # noqa: PLC0415
    from adscan_core.auth_outcome import SUCCESS, classify_kerberos_as  # noqa: PLC0415

    def guarded_get_kerberos_tgt(
        clientName: Any,  # noqa: N803 - impacket's signature
        password: Any,
        domain: Any,
        lmhash: Any,
        nthash: Any,
        aesKey: Any = "",  # noqa: N803
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        if kwargs.get("kerberoast_no_preauth"):
            return original(clientName, password, domain, lmhash, nthash, aesKey, *args, **kwargs)
        realm = str(domain or "")
        principal = _principal_name(clientName)
        secret = _secret_from(password, nthash, aesKey)
        if realm and principal:
            auth_attempt_guard.check_attempt(realm, principal, secret)
        try:
            result = original(clientName, password, domain, lmhash, nthash, aesKey, *args, **kwargs)
        except BaseException as exc:
            if realm and principal:
                auth_attempt_guard.record_verdict(
                    realm, principal, secret, classify_kerberos_as(_impacket_error_code(exc))
                )
            raise
        if realm and principal:
            auth_attempt_guard.record_verdict(realm, principal, secret, SUCCESS)
        return result

    setattr(guarded_get_kerberos_tgt, _MARKER, True)
    return guarded_get_kerberos_tgt


def _wrap_get_ntlmssp_type3(original: Callable[..., Any]) -> Callable[..., Any]:
    from adscan_core import auth_attempt_guard  # noqa: PLC0415

    def guarded_get_ntlmssp_type3(
        type1: Any,
        type2: Any,
        user: Any,
        password: Any,
        domain: Any,
        lmhash: Any = "",
        nthash: Any = "",
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        principal = str(user or "")
        realm = str(domain or "").strip()
        # A null session (no user) sends no secret. A host-local logon ("." or
        # no domain) is judged by the transport seam that knows the host.
        if principal and realm and realm != ".":
            auth_attempt_guard.check_attempt(
                realm, principal, _secret_from(password, nthash, "")
            )
        return original(type1, type2, user, password, domain, lmhash, nthash, *args, **kwargs)

    setattr(guarded_get_ntlmssp_type3, _MARKER, True)
    return guarded_get_ntlmssp_type3


def install_impacket_auth_guard() -> None:
    """Wrap impacket's NTLM and Kerberos secret senders. Idempotent, never raises."""
    global _INSTALLED  # noqa: PLW0603 - one process-wide patch
    if _INSTALLED:
        return
    with _LOCK:
        if _INSTALLED:
            return
        try:
            from impacket import ntlm  # noqa: PLC0415
            from impacket.krb5 import kerberosv5  # noqa: PLC0415
        except ImportError:
            return
        try:
            if not getattr(kerberosv5.getKerberosTGT, _MARKER, False):
                kerberosv5.getKerberosTGT = _wrap_get_kerberos_tgt(kerberosv5.getKerberosTGT)
            if not getattr(ntlm.getNTLMSSPType3, _MARKER, False):
                ntlm.getNTLMSSPType3 = _wrap_get_ntlmssp_type3(ntlm.getNTLMSSPType3)
        except Exception as exc:  # noqa: BLE001 - a failed patch must not break the caller
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return
        _INSTALLED = True
