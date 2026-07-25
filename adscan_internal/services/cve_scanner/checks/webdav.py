"""WebDAV redirector pipe enabler check.

Authenticated SMB enumeration of named pipes on ``IPC$``: the presence
of ``DAV RPC SERVICE`` indicates the WebClient (WebDAV redirector) is
running on the host. WebDAV is a powerful relay/coercion enabler — it
turns SMB-blocked egress into HTTP egress and is the prerequisite for
techniques such as ``PetitPotam``-over-HTTP relay to ADCS web
enrollment.

This check is authenticated. It uses :func:`smb_machine_with_fallback`
so it tolerates NTLM-disabled / Kerberos-only hosts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Evidence,
    Severity,
)
from adscan_internal.services.smb_transport import (
    SMBConfig,
    SMBTransportError,
    smb_machine_with_fallback,
)
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget


CVE_ID = "ADSCAN-WEBDAV-ENABLED"
AKA = "WebDAVEnabled"
CVSS_V3 = 5.3
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"

WEBDAV_PIPE = "DAV RPC SERVICE"


@dataclass(frozen=True)
class WebDAVProbeResult:
    """Outcome of one WebDAV pipe probe."""

    pipes_seen: tuple[str, ...]
    webdav_present: bool
    error: str | None = None


ProbeFn = Callable[..., Awaitable[WebDAVProbeResult]]


async def _probe_webdav(
    *,
    host: str,
    username: str | None,
    password: str | None,
    domain: str | None,
    auth_domain: str | None,
    nt_hash: str | None,
    kdc_ip: str | None,
    timeout: int = 30,
) -> WebDAVProbeResult:
    """Real probe — authenticated aiosmb session, list pipes on IPC$."""
    config = SMBConfig(
        target_ip=host,
        domain=domain,
        username=username,
        password=password,
        nt_hash=nt_hash,
        auth_domain=auth_domain,
        kdc_ip=kdc_ip,
        timeout=timeout,
    )
    pipes: list[str] = []
    try:
        async with smb_machine_with_fallback(config) as machine:
            async for name, err in machine.list_pipes():
                if err is not None:
                    continue
                if name:
                    pipes.append(str(name))
    except SMBTransportError as exc:
        return WebDAVProbeResult(
            pipes_seen=tuple(pipes),
            webdav_present=False,
            error=f"smb error: {exc}",
        )
    except Exception as exc:  # noqa: BLE001
        return WebDAVProbeResult(
            pipes_seen=tuple(pipes),
            webdav_present=False,
            error=f"unexpected error: {exc}",
        )

    webdav = any(p.upper() == WEBDAV_PIPE.upper() for p in pipes)
    return WebDAVProbeResult(
        pipes_seen=tuple(pipes),
        webdav_present=webdav,
    )


def classify(probe: WebDAVProbeResult) -> tuple[CVEStatus, str]:
    """Pure-logic classifier."""
    if probe.error and not probe.pipes_seen:
        return CVEStatus.ERROR, probe.error
    if probe.webdav_present:
        return CVEStatus.VULNERABLE, (
            "WebClient (WebDAV redirector) running — '\\PIPE\\DAV RPC SERVICE' "
            "exposed; relay/coercion enabler"
        )
    return CVEStatus.NOT_VULNERABLE, "WebDAV pipe absent"


class WebDAVCheck:
    """Authenticated WebDAV-pipe-presence check."""

    cve_id: str = CVE_ID

    def __init__(self, *, probe: ProbeFn | None = None, timeout: int = 30) -> None:
        self._probe = probe or _probe_webdav
        self._timeout = timeout

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        del ctx
        if creds is None:
            return [_error(target.host, "WebDAV probe requires authentication")]

        username = getattr(creds, "username", None)
        password = getattr(creds, "password", None)
        domain = getattr(creds, "target_domain", None) or getattr(creds, "domain", None)
        auth_domain = getattr(creds, "auth_domain", None) or domain
        nt_hash = getattr(creds, "nt_hash", None)
        kdc_ip = getattr(creds, "kdc_ip", None)

        print_info_verbose(f"[webdav] probing {mark_sensitive(target.host, 'host')}")
        try:
            probe = await self._probe(
                host=target.host,
                username=username,
                password=password,
                domain=domain,
                auth_domain=auth_domain,
                nt_hash=nt_hash,
                kdc_ip=kdc_ip,
                timeout=self._timeout,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[webdav] probe crashed against {target.host}: {exc}")
            return [_error(target.host, str(exc))]

        status, summary = classify(probe)
        payload = {
            "pipes_seen": list(probe.pipes_seen),
            "webdav_present": probe.webdav_present,
            "error": probe.error,
        }
        if status is CVEStatus.ERROR:
            return [_error(target.host, summary)]
        return [
            CVEResult(
                cve_id=CVE_ID,
                aka=AKA,
                host=target.host,
                status=status,
                severity=Severity.from_cvss(CVSS_V3),
                cvss_v3=CVSS_V3,
                cvss_vector=CVSS_VECTOR,
                evidence=Evidence(summary=summary, payload=payload),
            )
        ]


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
        evidence=Evidence(summary=f"WebDAV probe error: {message}", payload={}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "WEBDAV_PIPE",
    "WebDAVCheck",
    "WebDAVProbeResult",
    "classify",
]
