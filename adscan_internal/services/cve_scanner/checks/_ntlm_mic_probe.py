"""Low-level probe for the NTLM message-integrity (MIC) check, Drop the MIC.

Background (MS-NLMP 2.2.2.1, 3.1.5.1.2). A modern NTLM client appends a MIC to
its AUTHENTICATE message: an HMAC over all three NTLM messages that stops a man
in the middle from editing the exchange (for example removing the signing
request before relaying it). The MIC field is optional, so the only way a server
knows one must be there is the ``MsvAvFlags`` AV pair inside the NTLMv2
response, where bit ``0x2`` means "this message carries a MIC". That AV pair is
covered by the NTProofStr, i.e. by the user's password hash, so a relay cannot
alter it.

The two public flaws, both found by Preempt (now CrowdStrike):

* **CVE-2019-1040, "Drop the MIC"** (June 2019). A server accepted an
  AUTHENTICATE whose ``MsvAvFlags`` announced a MIC but which carried none: the
  relay simply removed the MIC, the Version field and the signing / key-exchange
  flags. The fix makes the server enforce the MIC whenever ``MsvAvFlags``
  announces it.
* **CVE-2019-1166, "Drop the MIC 2"** (October 2019), a bypass of that fix. The
  relay injects an ``MsvAvFlags`` pair with value 0 into the CHALLENGE's target
  information; the client echoes it into its NTLMv2 response next to its own
  ``MsvAvFlags`` = 0x2, both covered by its NTProofStr. The partially patched
  server read only the FIRST ``MsvAvFlags`` pair, concluded no MIC was present,
  and accepted the message without one.

CVE-2019-1040 is a server-side acceptance check, so it can be observed from the
client side with a valid credential and no relay: ADscan IS the client, computes
a genuine NTProofStr over an NTLMv2 response whose AV pairs carry the layout the
flaw needs, sends no MIC and no Version, and watches whether the server accepts
the session setup. ``MsvAvFlags = 0x2`` once, no MIC sent: a patched server
rejects (``STATUS_INVALID_PARAMETER`` on every Windows build measured by the
public scanner this mirrors, Fox-IT's ``cve-2019-1040-scanner``).

CVE-2019-1166 is NOT observable this way, and its check does not use this probe
(it reads the patch level, see ``drop_the_mic_2``). Measured 2026-11-06 on a
fully patched Server 2019 DC (17763.1935): with no MIC, the layouts none, (0)
and (0, 0x2) were accepted and (0x2, 0) was rejected. The patched server also
decides on the first ``MsvAvFlags`` value, and a first value of 0 is a
legitimate client that sends no MIC, so the duplicated layout is accepted on a
patched host exactly as on a vulnerable one. :data:`MIC_ANNOUNCEMENT_SHADOWED`
is kept for that characterization and for lab research only.

What ADscan must NOT do is corrupt any other field: an earlier version mutated
fixed byte offsets 72..88, which on impacket's AUTHENTICATE (no Version, no MIC)
are the user and workstation names, so every server rejected the sign-in for an
unrelated reason and the checks could never observe the MIC handling at all.

Mechanics. impacket's :class:`~impacket.smbconnection.SMBConnection` builds the
NTLM messages through module-level functions of :mod:`impacket.ntlm`. For one
login we replace ``getNTLMSSPType1`` (signing not requested, as in the relay
the CVE describes) and ``computeResponseNTLMv2`` (the AV pair layout). The
replacements only take effect on the thread that runs the probe; any other
thread that happens to use impacket NTLM during that window gets the original
behaviour. impacket never sets NEGOTIATE_VERSION here and never computes a MIC,
so the AUTHENTICATE carries neither field.
"""

from __future__ import annotations

import calendar
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

from adscan_core import telemetry
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:
    from adscan_internal.services.failing_auth_budget import FailingAuthBudget


# Module-level lock so concurrent probes against different hosts do not
# clobber each other's patch of the impacket module functions.
_PATCH_LOCK = threading.Lock()

#: MS-NLMP 2.2.2.1 AV pair ids used here (stable protocol constants).
_AV_EOL = 0x0000
_AV_NB_COMPUTER_NAME = 0x0001
_AV_DNS_COMPUTER_NAME = 0x0003
_AV_FLAGS = 0x0006
_AV_TIMESTAMP = 0x0007
_AV_TARGET_NAME = 0x0009

#: ``MsvAvFlags`` bit 0x2: "the AUTHENTICATE message carries a MIC".
MSV_AV_FLAG_MIC_PRESENT = 0x00000002

#: The ordered ``MsvAvFlags`` values a probe writes into its NTLMv2 response.
MsvAvFlagsLayout = tuple[int, ...]

#: CVE-2019-1040 (Drop the MIC): announce a MIC, send none.
MIC_ANNOUNCED_NOT_SENT: MsvAvFlagsLayout = (MSV_AV_FLAG_MIC_PRESENT,)

#: The CVE-2019-1166 (Drop the MIC 2) relay layout: an earlier ``MsvAvFlags`` = 0
#: shadows the client's own ``MsvAvFlags`` = 0x2, and no MIC is sent. NOT a
#: detection layout: a patched server accepts it too (see the module docstring).
MIC_ANNOUNCEMENT_SHADOWED: MsvAvFlagsLayout = (0, MSV_AV_FLAG_MIC_PRESENT)

#: The wrong-MIC control: send :data:`MIC_ANNOUNCED_NOT_SENT` with this MIC.
#: A host that accepts it does not verify the MIC at all, so its answer to the
#: two CVE probes says nothing about how it handles a MISSING MIC. Sixteen zero
#: bytes are never the HMAC of a real exchange in practice.
WRONG_MIC = b"\x00" * 16

#: VERSION structure (MS-NLMP 2.2.2.10) placed before a forged MIC: Windows
#: 10.0 build 17763, NTLM revision 15. Its content is not validated.
_CONTROL_VERSION = b"\x0a\x00\x63\x45\x00\x00\x00\x0f"


@dataclass(frozen=True)
class MICProbeResult:
    """Outcome of one MIC-less NTLM SMB session setup."""

    accepted: bool
    nt_status: int | None
    nt_status_name: str | None
    error: str | None = None
    notes: tuple[str, ...] = ()
    # True when the server rejected NTLM at negotiate/challenge time —
    # meaning NTLM is disabled on this host (GPO or config). The check
    # should return NotApplicable rather than Error.
    ntlm_not_available: bool = False
    # Set when the probe was NOT sent because the scanning account has no
    # lockout headroom for a sign-in the server may reject (see
    # ``failing_auth_budget``). The check reports the host as not assessed.
    skipped_reason: str | None = None


def _parse_av_pairs(target_info: bytes) -> list[tuple[int, bytes]]:
    """Parse MS-NLMP AV pairs, stopping at MsvAvEOL or the end of the buffer."""
    pairs: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 4 <= len(target_info):
        av_id, av_len = struct.unpack_from("<HH", target_info, offset)
        offset += 4
        if av_id == _AV_EOL:
            break
        pairs.append((av_id, bytes(target_info[offset : offset + av_len])))
        offset += av_len
    return pairs


def build_av_pairs(
    target_info: bytes,
    *,
    msv_av_flags: MsvAvFlagsLayout,
    service: str = "cifs",
    timestamp: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Return the client's AV pairs for the NTLMv2 response, and its timestamp.

    Mirrors what impacket's ``computeResponseNTLMv2`` sends (the server's target
    information, ``MsvAvTargetName`` = ``<service>/<host>`` for SPN target-name
    validation, ``MsvAvTimestamp``), then appends one ``MsvAvFlags`` pair per
    entry of ``msv_av_flags`` in order, then ``MsvAvEOL``. Any ``MsvAvFlags`` the
    server put in its challenge is dropped so the layout is exactly the one
    requested.

    Args:
        target_info: The CHALLENGE message's TargetInfo field.
        msv_av_flags: The ``MsvAvFlags`` values to write, in order.
        service: Service class for ``MsvAvTargetName``.
        timestamp: 8-byte FILETIME; defaults to the server's, else now.

    Returns:
        ``(av_pairs_bytes, timestamp)``.
    """
    pairs = [(av_id, value) for av_id, value in _parse_av_pairs(target_info) if av_id != _AV_FLAGS]
    by_id = dict(pairs)
    host = by_id.get(_AV_DNS_COMPUTER_NAME) or by_id.get(_AV_NB_COMPUTER_NAME) or b""
    target_name = f"{service}/".encode("utf-16le") + host
    if timestamp is None:
        timestamp = by_id.get(_AV_TIMESTAMP)
    if timestamp is None:
        timestamp = struct.pack("<q", 116444736000000000 + calendar.timegm(time.gmtime()) * 10000000)

    out: list[tuple[int, bytes]] = []
    for av_id, value in pairs:
        if av_id == _AV_TARGET_NAME:
            continue
        if av_id == _AV_TIMESTAMP:
            value = timestamp
        out.append((av_id, value))
    out.append((_AV_TARGET_NAME, target_name))
    if _AV_TIMESTAMP not in by_id:
        out.append((_AV_TIMESTAMP, timestamp))
    for flags in msv_av_flags:
        out.append((_AV_FLAGS, struct.pack("<I", flags)))

    data = b"".join(struct.pack("<HH", av_id, len(value)) + value for av_id, value in out)
    return data + struct.pack("<HH", _AV_EOL, 0), timestamp


def build_ntlmv2_response(
    *,
    server_challenge: bytes,
    client_challenge: bytes,
    target_info: bytes,
    user: str,
    password: str,
    domain: str,
    nt_hash: str = "",
    msv_av_flags: MsvAvFlagsLayout,
    service: str = "cifs",
) -> tuple[bytes, bytes, bytes]:
    """Compute a genuine NTLMv2 response over the requested AV pair layout.

    Same construction as impacket's ``computeResponseNTLMv2`` (MS-NLMP 3.3.2),
    only the AV pairs differ. Returns ``(nt_response, lm_response,
    session_base_key)``.
    """
    from impacket.ntlm import NTOWFv2, hmac_md5  # noqa: PLC0415

    response_key_nt = NTOWFv2(user, password, domain, nt_hash)
    av_pairs, timestamp = build_av_pairs(target_info, msv_av_flags=msv_av_flags, service=service)
    temp = (
        b"\x01"  # RespType
        + b"\x01"  # HiRespType
        + b"\x00" * 6  # Reserved1 + Reserved2
        + timestamp
        + client_challenge
        + b"\x00" * 4  # Reserved3
        + av_pairs
    )
    nt_proof_str = hmac_md5(response_key_nt, server_challenge + temp)
    nt_response = nt_proof_str + temp
    lm_response = hmac_md5(response_key_nt, server_challenge + client_challenge) + client_challenge
    session_base_key = hmac_md5(response_key_nt, nt_proof_str)
    return nt_response, lm_response, session_base_key


@contextmanager
def tampered_ntlm(
    msv_av_flags: MsvAvFlagsLayout, *, forged_mic: bytes | None = None
) -> Iterator[None]:
    """Make impacket build the probe's NTLM messages on the CALLING thread only.

    Inside the block, on the thread that entered it:

    * ``ntlm.getNTLMSSPType1`` requests no signing (no SIGN, ALWAYS_SIGN,
      SEAL or KEY_EXCH), as the relay the CVEs describe strips the request;
    * ``ntlm.computeResponseNTLMv2`` returns :func:`build_ntlmv2_response`
      over ``msv_av_flags``;
    * with ``forged_mic``, ``ntlm.getNTLMSSPType3`` adds a Version field and
      that 16-byte value as the MIC (the wrong-MIC control, see
      :data:`WRONG_MIC`). Without it, impacket never sets NEGOTIATE_VERSION in
      this flow and never computes a MIC, so the AUTHENTICATE has neither field.

    Any other thread calling those functions meanwhile gets impacket's original
    behaviour. Every function is restored on exit, even on error. Probes are
    serialised by ``_PATCH_LOCK``.
    """
    from adscan_internal.services.impacket_auth_guard import (  # noqa: PLC0415
        install_impacket_auth_guard,
    )

    install_impacket_auth_guard()
    from impacket import ntlm  # noqa: PLC0415

    if forged_mic is not None and len(forged_mic) != 16:
        raise ValueError("a MIC is 16 bytes")

    with _PATCH_LOCK:
        original_type1 = ntlm.getNTLMSSPType1
        original_response = ntlm.computeResponseNTLMv2
        original_type3 = ntlm.getNTLMSSPType3
        probe_thread = threading.get_ident()

        def _type1(workstation="", domain="", signingRequired=False, *args, **kwargs):  # noqa: N803
            if threading.get_ident() == probe_thread:
                signingRequired = False  # noqa: N806
            return original_type1(workstation, domain, signingRequired, *args, **kwargs)

        def _response(flags, serverChallenge, clientChallenge, serverName, domain, user,  # noqa: N803
                      password, lmhash="", nthash="", *args, **kwargs):
            if threading.get_ident() != probe_thread:
                return original_response(flags, serverChallenge, clientChallenge, serverName,
                                         domain, user, password, lmhash, nthash, *args, **kwargs)
            return build_ntlmv2_response(
                server_challenge=serverChallenge,
                client_challenge=clientChallenge,
                target_info=serverName,
                user=user,
                password=password,
                domain=domain,
                nt_hash=nthash,
                msv_av_flags=msv_av_flags,
                service=kwargs.get("service", "cifs"),
            )

        def _type3(*args, **kwargs):
            message, exported_key = original_type3(*args, **kwargs)
            if forged_mic is not None and threading.get_ident() == probe_thread:
                message["flags"] |= ntlm.NTLMSSP_NEGOTIATE_VERSION
                message["Version"] = _CONTROL_VERSION
                message["MIC"] = forged_mic
            return message, exported_key

        ntlm.getNTLMSSPType1 = _type1
        ntlm.computeResponseNTLMv2 = _response
        ntlm.getNTLMSSPType3 = _type3
        try:
            yield
        finally:
            ntlm.getNTLMSSPType1 = original_type1
            ntlm.computeResponseNTLMv2 = original_response
            ntlm.getNTLMSSPType3 = original_type3


def run_tampered_ntlm_smb_login(
    *,
    host: str,
    username: str,
    password: str | None,
    domain: str | None,
    nt_hash: str | None,
    msv_av_flags: MsvAvFlagsLayout,
    timeout: int = 15,
    budget: "FailingAuthBudget | None" = None,
    forged_mic: bytes | None = None,
) -> MICProbeResult:
    """Attempt a MIC-less NTLM SMB session setup; return the outcome.

    The credential is the scanning account's real one, so the domain controller
    sees a valid NTProofStr; the rejection, when it comes, is the target's MIC
    enforcement. The probe still reserves one attempt from ``budget``, the
    account's lockout headroom, before sending: the earlier, identity-corrupting
    version of this probe was measured counting a failed sign-in on GOAD, and
    that guard stays until the current construction is measured not to. With no
    budget, or none left, nothing is sent and the result carries
    ``skipped_reason``. An accepted login (vulnerable target) is refunded.

    Args:
        host: target IP / hostname.
        username, password, domain, nt_hash: credential material.
            ``password`` may be empty when ``nt_hash`` is supplied.
        msv_av_flags: The ``MsvAvFlags`` layout the NTLMv2 response carries
            (:data:`MIC_ANNOUNCED_NOT_SENT`; other layouts for lab research).
        timeout: SMB I/O timeout in seconds.
        budget: The scanning account's failing-sign-in budget.
        forged_mic: Send this 16-byte value as the MIC instead of none
            (the :data:`WRONG_MIC` control). Spends budget like the probe.

    Returns:
        :class:`MICProbeResult` with the server's NTSTATUS classification.
    """
    if budget is None:
        return MICProbeResult(
            accepted=False,
            nt_status=None,
            nt_status_name=None,
            skipped_reason="the scanning account's lockout headroom is unknown",
        )
    if not budget.try_reserve():
        return MICProbeResult(
            accepted=False,
            nt_status=None,
            nt_status_name=None,
            skipped_reason=budget.reason,
        )
    result = _run_tampered_ntlm_smb_login(
        host=host,
        username=username,
        password=password,
        domain=domain,
        nt_hash=nt_hash,
        msv_av_flags=msv_av_flags,
        timeout=timeout,
        forged_mic=forged_mic,
    )
    # An accepted login did not fail, and a host that does not offer NTLM never
    # received the AUTHENTICATE: both give the reservation back. Anything else
    # (a rejection, or an error whose cause is unknown) is counted as spent.
    if result.accepted or result.ntlm_not_available:
        budget.refund()
    return result


def _split_nt_hash(nt_hash: str | None) -> tuple[str, str]:
    """Return ``(lmhash, nthash)`` from ``NT`` or ``LM:NT`` material."""
    if not nt_hash:
        return "", ""
    if ":" in nt_hash:
        lmhash, _, nthash = nt_hash.partition(":")
        return lmhash, nthash
    return "", nt_hash


def _run_tampered_ntlm_smb_login(
    *,
    host: str,
    username: str,
    password: str | None,
    domain: str | None,
    nt_hash: str | None,
    msv_av_flags: MsvAvFlagsLayout,
    timeout: int,
    forged_mic: bytes | None = None,
) -> MICProbeResult:
    """Send the tampered session setup. Reached only through the budget seam."""
    try:
        from impacket.nt_errors import ERROR_MESSAGES, STATUS_SUCCESS
        from impacket.smbconnection import SessionError, SMBConnection
    except ImportError as exc:  # pragma: no cover
        return MICProbeResult(
            accepted=False,
            nt_status=None,
            nt_status_name=None,
            error=f"impacket missing: {exc}",
        )

    notes: list[str] = []
    nt_status: int | None = None
    nt_status_name: str | None = None
    accepted = False
    lmhash, nthash_value = _split_nt_hash(nt_hash)

    with tampered_ntlm(msv_av_flags, forged_mic=forged_mic):
        conn = SMBConnection(
            remoteName=host,
            remoteHost=host,
            sess_port=445,
            timeout=timeout,
        )
        try:
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

    return MICProbeResult(
        accepted=accepted,
        nt_status=nt_status,
        nt_status_name=nt_status_name,
        notes=tuple(notes),
    )


__all__ = [
    "MICProbeResult",
    "MIC_ANNOUNCED_NOT_SENT",
    "MIC_ANNOUNCEMENT_SHADOWED",
    "MSV_AV_FLAG_MIC_PRESENT",
    "WRONG_MIC",
    "MsvAvFlagsLayout",
    "build_av_pairs",
    "build_ntlmv2_response",
    "tampered_ntlm",
    "run_tampered_ntlm_smb_login",
]
