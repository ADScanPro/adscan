"""Check logic for an NTLM message-integrity (MIC) bypass probed by a sign-in.

CVE-2019-1040 ("Drop the MIC") is probed with one authenticated SMB session
setup whose NTLMv2 response carries a specific ``MsvAvFlags`` layout and no MIC
(see :mod:`._ntlm_mic_probe`); its module declares the subclass. CVE-2019-1166
("Drop the MIC 2") used this class until 13.2 and no longer does: no sign-in
tells a patched host from a vulnerable one for that CVE, so ``drop_the_mic_2``
reads the patch level instead.

Verdicts:

* accepted (``STATUS_SUCCESS``): the server took an AUTHENTICATE without the
  MIC it was told to expect, so a relay can strip the signing request.
  VULNERABLE.
* any NTSTATUS rejection: NOT VULNERABLE.
* no credential / NTLM not offered: NOT APPLICABLE.
* no lockout headroom for the attempt: SKIPPED, reported as not assessed.
* transport failure without a status: ERROR.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Callable, ClassVar

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_exception, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.checks._ntlm_mic_probe import (
    MICProbeResult,
    MsvAvFlagsLayout,
    run_tampered_ntlm_smb_login,
)
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Evidence,
    Severity,
)

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget


ProbeFn = Callable[..., MICProbeResult]


class NTLMMICBypassCheck:
    """Base class: one MIC-less NTLM session setup per host.

    Subclasses set the class attributes; nothing else is overridden.
    """

    cve_id: ClassVar[str]
    aka: ClassVar[str]
    #: Human name for log and evidence lines ("Drop the MIC").
    display_name: ClassVar[str]
    #: Greppable log marker, no square brackets (Rich markup).
    log_tag: ClassVar[str]
    cvss_v3: ClassVar[float]
    cvss_vector: ClassVar[str]
    msv_av_flags: ClassVar[MsvAvFlagsLayout]
    #: What the accepted message lacked, for the evidence line.
    accepted_summary: ClassVar[str]

    def __init__(self, *, probe: ProbeFn | None = None, timeout: int = 15) -> None:
        self._probe = probe or run_tampered_ntlm_smb_login
        self._timeout = timeout

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        if creds is None:
            return [
                self._result(
                    target.host,
                    CVEStatus.NOT_APPLICABLE,
                    f"{self.display_name} requires a valid credential to test",
                )
            ]

        username = getattr(creds, "username", None)
        password = getattr(creds, "password", None)
        domain = getattr(creds, "target_domain", None) or getattr(creds, "domain", None)
        nt_hash = getattr(creds, "nt_hash", None)
        if not username or (not password and not nt_hash):
            return [self._result(target.host, CVEStatus.NOT_APPLICABLE, "missing credential material")]

        print_info_verbose(f"{self.log_tag}: probing {mark_sensitive(target.host, 'host')}")
        try:
            result = await asyncio.to_thread(
                self._probe,
                host=target.host,
                username=username,
                password=password,
                domain=domain,
                nt_hash=nt_hash,
                msv_av_flags=self.msv_av_flags,
                timeout=self._timeout,
                # The scanning account's failing_auth_budget (lockout headroom):
                # the probe reserves one attempt before it sends anything.
                budget=getattr(ctx, "failing_auth_budget", None),
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(
                f"{self.log_tag}: probe crashed against "
                f"{mark_sensitive(target.host, 'host')}: {exc}"
            )
            return [self._error(target.host, str(exc))]
        return [self._result_from_probe(target.host, result)]

    def _result_from_probe(self, host: str, probe: MICProbeResult) -> CVEResult:
        payload = {
            "accepted": probe.accepted,
            "nt_status": probe.nt_status,
            "nt_status_name": probe.nt_status_name,
            "msv_av_flags": [f"0x{flags:08x}" for flags in self.msv_av_flags],
            "mic_sent": False,
            "notes": list(probe.notes),
            "error": probe.error,
        }
        if probe.skipped_reason:
            summary = (
                "not assessed: this check sends a sign-in that a patched server rejects "
                f"and counts against the scanning account, and {probe.skipped_reason}"
            )
            return self._result(
                host, CVEStatus.SKIPPED, summary, payload={"reason": probe.skipped_reason}
            )
        if probe.ntlm_not_available:
            return self._result(
                host, CVEStatus.NOT_APPLICABLE, "NTLM disabled on this host, check not applicable"
            )
        if probe.error and probe.nt_status is None:
            return self._error(host, probe.error)
        if probe.accepted:
            return self._result(host, CVEStatus.VULNERABLE, self.accepted_summary, payload=payload)
        return self._result(
            host,
            CVEStatus.NOT_VULNERABLE,
            "server rejected the AUTHENTICATE message without its MIC: "
            f"{probe.nt_status_name or 'rejected'}",
            payload=payload,
        )

    def _result(
        self,
        host: str,
        status: CVEStatus,
        summary: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> CVEResult:
        return CVEResult(
            cve_id=self.cve_id,
            aka=self.aka,
            host=host,
            status=status,
            severity=Severity.from_cvss(self.cvss_v3),
            cvss_v3=self.cvss_v3,
            cvss_vector=self.cvss_vector,
            evidence=Evidence(
                summary=summary, payload=payload if payload is not None else {"reason": summary}
            ),
        )

    def _error(self, host: str, message: str) -> CVEResult:
        return CVEResult(
            cve_id=self.cve_id,
            aka=self.aka,
            host=host,
            status=CVEStatus.ERROR,
            severity=Severity.from_cvss(self.cvss_v3),
            cvss_v3=self.cvss_v3,
            cvss_vector=self.cvss_vector,
            error=message,
            evidence=Evidence(summary=f"{self.display_name} error: {message}", payload={}),
        )


__all__ = ["NTLMMICBypassCheck", "ProbeFn"]
