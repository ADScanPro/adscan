"""Drop the MIC (CVE-2019-1166) native check.

NTLM relay enabler. The vulnerability lets an attacker remove the MIC
(message integrity code) field from the AUTHENTICATE_MESSAGE before
forwarding it; an unpatched server accepts the message regardless.

This check performs an authenticated SMB session-setup against the
target with the MIC field zeroed out. ``STATUS_SUCCESS`` confirms
vulnerability; patched servers reject with ``STATUS_INVALID_PARAMETER``
or ``STATUS_LOGON_FAILURE``.

Authenticated probe — requires a valid credential (the underlying
exploit is a relay enabler, but detection still needs a valid NTLM
auth flow to run end-to-end).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.checks._ntlm_mic_probe import (
    MICProbeResult,
    run_tampered_ntlm_smb_login,
)
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Evidence,
    Severity,
)
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget


CVE_ID = "CVE-2019-1166"
AKA = "DropTheMIC"
CVSS_V3 = 6.8
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"


def zero_mic(type3_bytes: bytes) -> bytes:
    """Mutator: zero the 16-byte MIC inside the AUTHENTICATE_MESSAGE.

    AUTHENTICATE_MESSAGE layout (offsets from start):

    *  0..7   Signature ('NTLMSSP\\0')
    *  8..11  MessageType (0x00000003)
    *  ...
    * 60..63  NegotiateFlags
    * 64..71  Version (when NEGOTIATE_VERSION flag set)
    * 72..87  MIC (16 bytes, when present)

    impacket emits the MIC at offset 72 when version is present. We
    zero it in-place; the rest of the payload is preserved bit-exact.
    """
    if len(type3_bytes) < 88:
        return type3_bytes
    return type3_bytes[:72] + b"\x00" * 16 + type3_bytes[88:]


ProbeFn = Callable[..., MICProbeResult]


class DropTheMICCheck:
    """Native Drop-the-MIC detection check."""

    cve_id: str = CVE_ID

    def __init__(self, *, probe: ProbeFn | None = None, timeout: int = 15) -> None:
        self._probe = probe or run_tampered_ntlm_smb_login
        self._timeout = timeout

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        del ctx
        if creds is None:
            return [
                _not_applicable(
                    target.host, "Drop-the-MIC requires a valid credential to test"
                )
            ]

        username = getattr(creds, "username", None)
        password = getattr(creds, "password", None)
        domain = getattr(creds, "target_domain", None) or getattr(creds, "domain", None)
        nt_hash = getattr(creds, "nt_hash", None)
        if not username or (not password and not nt_hash):
            return [_not_applicable(target.host, "missing credential material")]

        print_info_verbose(
            f"[drop-the-mic] probing {mark_sensitive(target.host, 'host')}"
        )
        try:
            result = await asyncio.to_thread(
                self._probe,
                host=target.host,
                username=username,
                password=password,
                domain=domain,
                nt_hash=nt_hash,
                mic_mutator=zero_mic,
                timeout=self._timeout,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[drop-the-mic] probe crashed against {target.host}: {exc}")
            return [_error(target.host, str(exc))]
        return [_result_from_probe(target.host, result)]


def _result_from_probe(host: str, probe: MICProbeResult) -> CVEResult:
    payload = {
        "accepted": probe.accepted,
        "nt_status": probe.nt_status,
        "nt_status_name": probe.nt_status_name,
        "notes": list(probe.notes),
        "error": probe.error,
    }
    if probe.ntlm_not_available:
        return _not_applicable(host, "NTLM disabled on this host — check not applicable")
    if probe.error and probe.nt_status is None:
        return _error(host, probe.error)
    if probe.accepted:
        return CVEResult(
            cve_id=CVE_ID,
            aka=AKA,
            host=host,
            status=CVEStatus.VULNERABLE,
            severity=Severity.from_cvss(CVSS_V3),
            cvss_v3=CVSS_V3,
            cvss_vector=CVSS_VECTOR,
            evidence=Evidence(
                summary=(
                    "server accepted MIC-stripped AUTHENTICATE_MESSAGE — "
                    "Drop-the-MIC vulnerable"
                ),
                payload=payload,
            ),
        )
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.NOT_VULNERABLE,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        evidence=Evidence(
            summary=(
                f"server rejected MIC-stripped AUTHENTICATE — "
                f"{probe.nt_status_name or 'patched'}"
            ),
            payload=payload,
        ),
    )


def _not_applicable(host: str, reason: str) -> CVEResult:
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.NOT_APPLICABLE,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        evidence=Evidence(summary=reason, payload={"reason": reason}),
    )


def _error(host: str, message: str) -> CVEResult:
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.ERROR,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        error=message,
        evidence=Evidence(summary=f"Drop-the-MIC error: {message}", payload={}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "DropTheMICCheck",
    "zero_mic",
]
