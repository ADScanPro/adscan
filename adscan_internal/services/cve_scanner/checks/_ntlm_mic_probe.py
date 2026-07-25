"""Shared low-level helper for the Drop-the-MIC / NTLM-Reflection checks.

Both checks need to:

1. Run a normal NTLM SMB session-setup against the target.
2. Mutate the AUTHENTICATE_MESSAGE before it is sent — either by
   stripping the MIC (Drop the MIC, CVE-2019-1166) or by flipping bits
   inside the MIC (NTLM Reflection, CVE-2019-1040).
3. Observe whether the server accepts the tampered AUTHENTICATE
   (``STATUS_SUCCESS``) or rejects it
   (``STATUS_INVALID_PARAMETER`` / ``STATUS_LOGON_FAILURE``).

We do this by temporarily wrapping :func:`impacket.ntlm.getNTLMSSPType3`
at the module level. impacket's :class:`smbconnection.SMBConnection`
calls into that helper while building the AUTHENTICATE token; replacing
it for the duration of one login lets us mutate the bytes without
forking impacket. The wrapper is removed in a ``finally`` so concurrent
checks against other hosts are unaffected.

This module exposes a synchronous probe used from ``asyncio.to_thread``
in the two CVE checks. The probe pattern matches the rest of the CVE
scanner (see ``zerologon.py``).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_exception


# Module-level lock so concurrent probes against different hosts do not
# clobber each other's monkey-patch.
_PATCH_LOCK = threading.Lock()


@dataclass(frozen=True)
class MICProbeResult:
    """Outcome of one tampered-NTLM SMB session-setup."""

    accepted: bool
    nt_status: int | None
    nt_status_name: str | None
    error: str | None = None
    notes: tuple[str, ...] = ()
    # True when the server rejected NTLM at negotiate/challenge time —
    # meaning NTLM is disabled on this host (GPO or config). The CVE check
    # should return NotApplicable rather than Error.
    ntlm_not_available: bool = False


# AUTHENTICATE_MESSAGE mutator: receives the type3 NTLM message bytes
# and returns mutated bytes. Both checks supply their own mutator.
MICMutator = Callable[[bytes], bytes]


def run_tampered_ntlm_smb_login(
    *,
    host: str,
    username: str,
    password: str | None,
    domain: str | None,
    nt_hash: str | None,
    mic_mutator: MICMutator,
    timeout: int = 15,
) -> MICProbeResult:
    """Attempt a tampered NTLM SMB session-setup; return the outcome.

    Args:
        host: target IP / hostname.
        username, password, domain, nt_hash: credential material.
            ``password`` may be empty when ``nt_hash`` is supplied.
        mic_mutator: callable that mutates the raw type3 bytes before
            they are sent. Examples: zero out the MIC field (Drop the
            MIC), flip a MIC bit (NTLM Reflection).
        timeout: SMB I/O timeout in seconds.

    Returns:
        :class:`MICProbeResult` with the server's NTSTATUS classification.
    """
    try:
        from impacket import ntlm
        from impacket.nt_errors import ERROR_MESSAGES, STATUS_SUCCESS
        from impacket.smbconnection import SessionError, SMBConnection
    except ImportError as exc:  # pragma: no cover
        return MICProbeResult(
            accepted=False,
            nt_status=None,
            nt_status_name=None,
            error=f"impacket missing: {exc}",
        )

    original = ntlm.getNTLMSSPType3
    notes: list[str] = []

    def _patched(*args, **kwargs):
        type3, exported = original(*args, **kwargs)
        try:
            raw = type3.getData()
        except Exception:  # noqa: BLE001
            return type3, exported
        try:
            mutated = mic_mutator(raw)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"mic mutator raised: {exc}")
            return type3, exported
        # Re-pack the mutated bytes into a fresh AUTHENTICATE_MESSAGE.
        new_type3 = ntlm.NTLMAuthChallengeResponse()
        try:
            new_type3.fromString(mutated)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"could not re-parse mutated type3: {exc}")
            return type3, exported
        return new_type3, exported

    nt_status: int | None = None
    nt_status_name: str | None = None
    accepted = False

    with _PATCH_LOCK:
        ntlm.getNTLMSSPType3 = _patched
        try:
            conn = SMBConnection(
                remoteName=host,
                remoteHost=host,
                sess_port=445,
                timeout=timeout,
            )
            try:
                lmhash = ""
                nthash_value = ""
                if nt_hash:
                    if ":" in nt_hash:
                        lmhash, _, nthash_value = nt_hash.partition(":")
                    else:
                        nthash_value = nt_hash
                conn.login(
                    user=username,
                    password=password or "",
                    domain=domain or "",
                    lmhash=lmhash,
                    nthash=nthash_value,
                )
                accepted = True
                nt_status = STATUS_SUCCESS
                nt_status_name = "STATUS_SUCCESS"
            except SessionError as exc:
                code = getattr(exc, "error", None)
                if isinstance(code, int):
                    nt_status = code
                    nt_status_name = ERROR_MESSAGES.get(code, (None,))[0]
                else:
                    nt_status_name = str(exc)
                notes.append(f"SessionError: {exc}")
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                exc_str = str(exc).lower()
                # Detect NTLM disabled at negotiate/challenge level.
                # impacket raises generic Exception (not SessionError) when
                # the server declines NTLM in the SPNEGO negTokenInit or when
                # the challenge token cannot be decoded because NTLM is not
                # offered. Typical strings: "non-decodable ntlm challenge",
                # "ntlm not supported", "kerberos only", "mechanism not available".
                ntlm_disabled = any(
                    marker in exc_str
                    for marker in (
                        "non-decodable ntlm",
                        "ntlm not supported",
                        "ntlm is not supported",
                        "kerberos only",
                        "mechanism not available",
                        "no common mechs",
                        "unsupported security mechanism",
                    )
                )
                return MICProbeResult(
                    accepted=False,
                    nt_status=None,
                    nt_status_name=None,
                    error=str(exc),
                    notes=tuple(notes),
                    ntlm_not_available=ntlm_disabled,
                )
            finally:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
        finally:
            ntlm.getNTLMSSPType3 = original

    return MICProbeResult(
        accepted=accepted,
        nt_status=nt_status,
        nt_status_name=nt_status_name,
        notes=tuple(notes),
    )


__all__ = [
    "MICMutator",
    "MICProbeResult",
    "run_tampered_ntlm_smb_login",
]
