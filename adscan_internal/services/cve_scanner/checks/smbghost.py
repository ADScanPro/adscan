"""SMBGhost (CVE-2020-0796) native check.

Probe-only: send an SMB 3.1.1 ``NEGOTIATE`` request advertising
compression capabilities and inspect the server reply for an
``SMB2_COMPRESSION_CAPABILITIES`` context whose
``CompressionAlgorithmCount > 0``. We never send the malformed
compressed-payload exploit packet — only the negotiate.

The result is corroborated with the AD-side ``operatingSystemVersion``
(via ``ScanContext.extras['os_versions']``) when available so we can
distinguish "compression on, but build outside the SMBGhost window"
from "compression on AND build is 1903/1909". Without an OS-version
hint, compression-enabled SMB 3.1.1 alone is reported as Vulnerable
since that is the canonical signal — the LDAP cross-check only
*demotes* the finding, never raises a clean host to vulnerable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.checks._build_matrix import (
    parse_base_build,
    smbghost_build_signal,
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


CVE_ID = "CVE-2020-0796"
AKA = "SMBGhost"
CVSS_V3 = 10.0
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@dataclass(frozen=True)
class SMBGhostProbeResult:
    """Outcome of one SMB 3.1.1 NEGOTIATE-only probe."""

    smb311_supported: bool
    compression_algorithm_count: int
    compression_algorithms: tuple[int, ...]
    server_os_version: str | None = None
    error: str | None = None


ProbeFn = Callable[..., Awaitable[SMBGhostProbeResult]]


async def _probe_smbghost(
    *, host: str, port: int = 445, timeout: float = 15.0
) -> SMBGhostProbeResult:
    """Real aiosmb-based SMB 3.1.1 NEGOTIATE probe."""
    try:
        from aiosmb.commons.connection.target import SMBTarget
        from aiosmb.connection import SMBConnection
        from aiosmb.protocol.common import NegotiateDialects
    except ImportError as exc:  # pragma: no cover
        return SMBGhostProbeResult(
            smb311_supported=False,
            compression_algorithm_count=0,
            compression_algorithms=(),
            error=f"aiosmb missing: {exc}",
        )

    target = SMBTarget(ip=host, port=port, timeout=int(timeout))
    # SMBConnection.__init__ signature (vendor/aiosmb/aiosmb/connection.py:145):
    #   def __init__(self, gssapi, target, preserve_gssapi=True, nosign=False)
    # For an unauthenticated negotiate-only probe gssapi is None.
    connection = SMBConnection(None, target, nosign=True)
    try:
        res, _sign_en, _sign_req, rply, err = await connection.protocol_test(
            [NegotiateDialects.SMB311]
        )
    except Exception as exc:  # noqa: BLE001
        return SMBGhostProbeResult(
            smb311_supported=False,
            compression_algorithm_count=0,
            compression_algorithms=(),
            error=f"protocol_test failed: {exc}",
        )

    if not res or rply is None or err is not None:
        return SMBGhostProbeResult(
            smb311_supported=False,
            compression_algorithm_count=0,
            compression_algorithms=(),
            error=str(err) if err else "negotiate failed",
        )

    cmd = getattr(rply, "command", None)
    ctx_list = getattr(cmd, "NegotiateContextList", []) or []
    compression_count = 0
    compression_algos: list[int] = []
    # SMB2ContextType.COMPRESSION_CAPABILITIES == 0x0003 (see
    # vendor/aiosmb/aiosmb/protocol/smb2/commands/negotiate.py:152).
    # ContextType on the parsed reply is the enum, not a raw int — compare
    # via .value to stay enum-agnostic if aiosmb ever swaps to IntEnum.
    from aiosmb.protocol.smb2.commands.negotiate import SMB2ContextType

    for ctx in ctx_list:
        ctx_type = getattr(ctx, "ContextType", None)
        ctx_type_int = (
            ctx_type.value
            if isinstance(ctx_type, SMB2ContextType)
            else int(ctx_type or 0)
        )
        if ctx_type_int == SMB2ContextType.COMPRESSION_CAPABILITIES.value:
            algos = list(getattr(ctx, "CompressionAlgorithms", []) or [])
            # CompressionAlgorithms entries may be SMB2CompressionType enum
            # values (Enum, not IntEnum — int() crashes). Mirror the
            # ContextType pattern above and prefer .value when present.
            compression_algos.extend(
                getattr(a, "value", a) if hasattr(a, "value") else int(a)
                for a in algos
            )
            count = getattr(ctx, "CompressionAlgorithmCount", len(algos))
            compression_count = max(compression_count, int(count))

    return SMBGhostProbeResult(
        smb311_supported=True,
        compression_algorithm_count=compression_count,
        compression_algorithms=tuple(compression_algos),
        server_os_version=None,
    )


def classify(
    probe: SMBGhostProbeResult,
    *,
    os_version_raw: str | None = None,
) -> tuple[CVEStatus, str]:
    """Pure-logic classifier — independently testable.

    Compression caps in the SMB 3.1.1 reply is the canonical signal.
    OS-version corroboration only DEMOTES findings outside the 1903/1909
    window — it never promotes a clean host.
    """
    if probe.error and not probe.smb311_supported:
        return CVEStatus.ERROR, probe.error
    if not probe.smb311_supported:
        return CVEStatus.NOT_APPLICABLE, "server does not negotiate SMB 3.1.1"
    if probe.compression_algorithm_count <= 0:
        return CVEStatus.NOT_VULNERABLE, "SMB 3.1.1 supported but compression disabled"
    in_window, why = smbghost_build_signal(os_version_raw)
    if os_version_raw is None:
        return CVEStatus.VULNERABLE, (
            "compression-enabled SMB 3.1.1 reply — SMBGhost surface present "
            "(OS build unknown, cannot corroborate patch-window)"
        )
    if in_window:
        return CVEStatus.VULNERABLE, ("compression-enabled SMB 3.1.1 reply AND " + why)
    return CVEStatus.NOT_VULNERABLE, ("compression-enabled SMB 3.1.1 reply but " + why)


class SMBGhostCheck:
    """Probe-only SMBGhost detection."""

    cve_id: str = CVE_ID

    def __init__(self, *, probe: ProbeFn | None = None, timeout: float = 15.0) -> None:
        self._probe = probe or _probe_smbghost
        self._timeout = timeout

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        del creds
        print_info_verbose(f"[smbghost] probing {mark_sensitive(target.host, 'host')}")
        try:
            probe_result = await self._probe(host=target.host, timeout=self._timeout)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[smbghost] probe crashed against {target.host}: {exc}")
            return [_error(target.host, str(exc))]

        os_versions: dict[str, str] = {}
        if ctx is not None:
            extras = getattr(ctx, "extras", None) or {}
            os_versions = dict(extras.get("os_versions") or {})
        os_version_raw = (
            os_versions.get(target.host)
            or os_versions.get((target.display_name or "").lower())
            or probe_result.server_os_version
        )
        status, summary = classify(probe_result, os_version_raw=os_version_raw)
        return [
            _result(
                target.host,
                status=status,
                summary=summary,
                probe=probe_result,
                os_version_raw=os_version_raw,
            )
        ]


def _result(
    host: str,
    *,
    status: CVEStatus,
    summary: str,
    probe: SMBGhostProbeResult,
    os_version_raw: str | None,
) -> CVEResult:
    payload = {
        "smb311_supported": probe.smb311_supported,
        "compression_algorithm_count": probe.compression_algorithm_count,
        "compression_algorithms": list(probe.compression_algorithms),
        "os_version_raw": os_version_raw,
        "os_base_build": parse_base_build(os_version_raw),
        "error": probe.error,
    }
    if status is CVEStatus.ERROR:
        return CVEResult(
            cve_id=CVE_ID,
            aka=AKA,
            host=host,
            status=CVEStatus.ERROR,
            severity=Severity.from_cvss(CVSS_V3),
            cvss_v3=CVSS_V3,
            cvss_vector=CVSS_VECTOR,
            error=summary,
            evidence=Evidence(
                summary=f"SMBGhost probe error: {summary}", payload=payload
            ),
        )
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=status,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        evidence=Evidence(summary=summary, payload=payload),
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
        evidence=Evidence(summary=f"SMBGhost probe error: {message}", payload={}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "SMBGhostCheck",
    "SMBGhostProbeResult",
    "classify",
]
