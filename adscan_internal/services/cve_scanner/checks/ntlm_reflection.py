"""NTLM Reflection (CVE-2019-1040) native check.

NTLM relay/MIC tampering enabler. CVE-2019-1040 lets an attacker flip
bits inside the AUTHENTICATE_MESSAGE's MIC; an unpatched server still
accepts the auth because the MIC is not actually validated against the
negotiated message stream.

Detection: perform an authenticated SMB session-setup with one byte of
the MIC flipped. ``STATUS_SUCCESS`` confirms vulnerability; patched
servers reject with ``STATUS_INVALID_PARAMETER`` /
``STATUS_LOGON_FAILURE``.

The mutation is intentionally smaller than Drop-the-MIC's full strip:
this check exercises the *MIC validation* code path specifically,
distinguishing CVE-2019-1040 from CVE-2019-1166.
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


CVE_ID = "CVE-2019-1040"
AKA = "NTLMReflection"
CVSS_V3 = 5.9
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"


def flip_mic_bit(type3_bytes: bytes) -> bytes:
    """Mutator: XOR one byte inside the AUTHENTICATE_MESSAGE MIC field.

    The MIC sits at bytes 72..87 (after Signature/MessageType/fields/
    NegotiateFlags/Version). We flip the low bit of the first MIC byte
    so the message is structurally identical to a valid one but its
    integrity tag no longer matches.
    """
    if len(type3_bytes) < 88:
        return type3_bytes
    mutated = bytearray(type3_bytes)
    mutated[72] ^= 0x01
    return bytes(mutated)


ProbeFn = Callable[..., MICProbeResult]


class NTLMReflectionCheck:
    """Native NTLM Reflection (CVE-2019-1040) detection check."""

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
                    target.host, "NTLM Reflection requires a valid credential to test"
                )
            ]

        username = getattr(creds, "username", None)
        password = getattr(creds, "password", None)
        domain = getattr(creds, "target_domain", None) or getattr(creds, "domain", None)
        nt_hash = getattr(creds, "nt_hash", None)
        if not username or (not password and not nt_hash):
            return [_not_applicable(target.host, "missing credential material")]

        print_info_verbose(
            f"[ntlm-reflection] probing {mark_sensitive(target.host, 'host')}"
        )
        try:
            result = await asyncio.to_thread(
                self._probe,
                host=target.host,
                username=username,
                password=password,
                domain=domain,
                nt_hash=nt_hash,
                mic_mutator=flip_mic_bit,
                timeout=self._timeout,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[ntlm-reflection] probe crashed against {target.host}: {exc}")
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
                    "server accepted MIC-tampered AUTHENTICATE_MESSAGE — "
                    "NTLM Reflection (CVE-2019-1040) vulnerable"
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
                f"server rejected MIC-tampered AUTHENTICATE — "
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
        evidence=Evidence(summary=f"NTLM Reflection error: {message}", payload={}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "NTLMReflectionCheck",
    "flip_mic_bit",
]
