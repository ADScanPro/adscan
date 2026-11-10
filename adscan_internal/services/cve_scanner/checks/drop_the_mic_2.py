"""Drop the MIC 2 (CVE-2019-1166) native check, graded from the patch level.

The flaw (Preempt / CrowdStrike, October 2019) bypasses the CVE-2019-1040 fix
during a relay. The attacker injects an ``MsvAvFlags`` AV pair with value 0 into
the CHALLENGE's target information; the client echoes it into its NTLMv2
response ahead of its own ``MsvAvFlags`` = 0x2, so both sit under its genuine
NTProofStr. A vulnerable server read only the first pair, concluded the message
carried no MIC, and accepted it with the MIC removed. Microsoft's October 2019
update "addresses the vulnerability by hardening NTLM MIC protection on the
server-side" (MSRC, CVE-2019-1166).

Why this check sends no sign-in probe
-------------------------------------
A direct sign-in probe cannot tell a patched server from a vulnerable one. The
probe that ADscan carried until 13.2 sent ``MsvAvFlags`` = 0 then 0x2 with no
MIC; on a fully patched Windows Server 2019 DC (build 17763.1935, May 2021
cumulative update, measured 2026-11-06) the server ACCEPTED it, while the
CVE-2019-1040 layout (0x2 alone, no MIC) was rejected with
``STATUS_INVALID_PARAMETER``. The flag-layout characterization on that host:

=============  ============================
MsvAvFlags     answer (no MIC in each case)
=============  ============================
none           accepted
(0)            accepted
(0x2, 0)       rejected
(0, 0x2)       accepted
=============  ============================

The patched server also decides on the FIRST ``MsvAvFlags`` value, and a first
value of 0 is what a legitimate client that sends no MIC presents, so it is
accepted. Whatever the October 2019 hardening checks, it is not observable from
a sign-in whose sender is also the client: no public scanner (NetExec ships only
the CVE-2019-1040 ``remove-mic`` module, impacket's ``--remove-mic`` targets
CVE-2019-1040) and no published patch analysis gives a remote discriminator. The
probe reported every patched host as vulnerable, so it was removed.

What the check does instead
---------------------------
It reads the host's patch level (``CurrentBuildNumber`` and ``UBR`` over Remote
Registry, :mod:`._os_patch_level`) and compares the revision with the October
8, 2019 cumulative update of that build (each revision in the table matches the
"OS Build" Microsoft publishes for that KB):

* below the fix → ``VULNERABLE``, an INFERENCE (catalog
  ``detection_basis="inferred"`` grades it High, and the evidence line says
  it was inferred from the patch level, and whether that level was read with
  administrative access). The CVE has no report finding key,
  so no compliance control is graded on it;
* at or above it, or a build released after it → ``NOT_VULNERABLE``;
* anything not read or not modelled (Remote Registry stopped or denied, the
  6.x builds serviced by monthly rollups) → ``SKIPPED``, reported as not
  assessed with the reason. It never becomes a verdict.

Nothing is sent that a patched host rejects, so the check draws nothing from the
scanning account's failing-auth budget.

The read goes through the run's per-host cache (``ScanContext.patch_level``,
:mod:`..host_patch_level`): one read per host serves every patch-level check,
made with an administrator of the host when ADscan holds one (the read a
default host answers), with the scan credential as the fallback.

References:
    https://nvd.nist.gov/vuln/detail/CVE-2019-1166
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1166
    https://www.crowdstrike.com/en-us/blog/active-directory-ntlm-attack-security-advisory/
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_exception, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.checks._os_patch_level import (
    PATCHED,
    UNPATCHED,
    OSVersionRead,
    classify_patch_level,
    patch_level_basis,
    read_os_version_over_smb,
    read_os_version_with_config,
)
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Evidence,
    Severity,
)

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget

CVE_ID = "CVE-2019-1166"
AKA = "DropTheMIC2"
# NVD (NIST) CVSS 3.1 base score.
CVSS_V3 = 5.9
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"

#: First UBR of each Windows build that carries the October 8, 2019 update, the
#: one MSRC lists for CVE-2019-1166. Each value is the "OS Build" Microsoft
#: publishes for the KB: KB4520011 10240.18368, KB4519998 14393.3274,
#: KB4520010 15063.2108, KB4520004 16299.1451, KB4520008 17134.1069,
#: KB4519338 17763.805, KB4517389 18362.418. 18363 (1909) shares 18362's
#: servicing, so the same revision carries the fix. Windows 7 / 8.1 and Server
#: 2008 / 2012 / 2012 R2 take monthly rollups and are not modelled.
DROP_THE_MIC_2_FIXED_UBR_BY_BUILD: dict[int, int] = {
    10240: 18368,
    14393: 3274,
    15063: 2108,
    16299: 1451,
    17134: 1069,
    17763: 805,
    18362: 418,
    18363: 418,
}
#: Windows 10 2004 (19041, May 2020) and every later build, Server 2022 (20348)
#: included, shipped after the fix.
FIRST_BUILD_RELEASED_FIXED = 19041

#: Why a sign-in probe is not used, carried in every result's evidence.
NO_REMOTE_DISCRIMINATOR = (
    "a sign-in probe cannot tell a patched server from a vulnerable one for this "
    "CVE, so the verdict follows the host's patch level"
)

ReadFn = Callable[..., Awaitable[OSVersionRead]]


def patch_status(build: int | None, ubr: int | None) -> str:
    """``patched`` / ``unpatched`` / ``unknown`` against the October 2019 update."""
    return classify_patch_level(
        build,
        ubr,
        fixed_ubr_by_build=DROP_THE_MIC_2_FIXED_UBR_BY_BUILD,
        first_build_released_fixed=FIRST_BUILD_RELEASED_FIXED,
    )


def classify(read: OSVersionRead) -> tuple[CVEStatus, str]:
    """Pure verdict from the patch level one host reported."""
    status = patch_status(read.build, read.ubr)
    if status == UNPATCHED:
        return CVEStatus.VULNERABLE, (
            f"build {read.build}.{read.ubr} is below the October 2019 update that "
            f"fixes Drop the MIC 2 (CVE-2019-1166); {patch_level_basis(read)}"
        )
    if status == PATCHED:
        return CVEStatus.NOT_VULNERABLE, (
            f"build {read.build}.{read.ubr} carries the October 2019 update that "
            f"fixes Drop the MIC 2 (CVE-2019-1166); {patch_level_basis(read)}"
        )
    if read.build is None:
        detail = read.error or read.reason or "no build reported"
        return CVEStatus.SKIPPED, (
            f"not assessed: {NO_REMOTE_DISCRIMINATOR}, and the patch level could not "
            f"be read ({detail})"
        )
    return CVEStatus.SKIPPED, (
        f"not assessed: {NO_REMOTE_DISCRIMINATOR}, and build {read.build}"
        f"{'.' + str(read.ubr) if read.ubr is not None else ''} is outside the "
        "fix table (monthly-rollup or pre-release build)"
    )


class DropTheMIC2Check:
    """Drop the MIC 2 (CVE-2019-1166), inferred from the patch level."""

    cve_id: str = CVE_ID
    aka: str = AKA
    display_name: str = "Drop the MIC 2"
    log_tag: str = "drop-the-mic-2"
    cvss_v3: float = CVSS_V3
    cvss_vector: str = CVSS_VECTOR
    #: Graded from the host's patch level: the post-collection re-run
    #: (``patch_level_rerun``) re-evaluates it once administrator access exists.
    reads_patch_level: bool = True

    def __init__(
        self,
        *,
        read: ReadFn | None = None,
        admin_read: Callable[[Any], Awaitable[OSVersionRead]] | None = None,
        timeout: int = 30,
    ) -> None:
        self._read = read or read_os_version_over_smb
        # An administrator's session (``SMBConfig``), used through the run's cache.
        self._admin_read = admin_read or read_os_version_with_config
        self._timeout = timeout

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        """Read the patch level of ``target`` and grade it."""
        if creds is None:
            return [
                _result(
                    target.host,
                    CVEStatus.NOT_APPLICABLE,
                    "Drop the MIC 2 requires a valid credential to read the patch level",
                )
            ]
        username = getattr(creds, "username", None)
        password = getattr(creds, "password", None)
        nt_hash = getattr(creds, "nt_hash", None)
        if not username or (not password and not nt_hash):
            return [_result(target.host, CVEStatus.NOT_APPLICABLE, "missing credential material")]

        from adscan_internal.services.cve_scanner.checks.webdav import (  # noqa: PLC0415
            _resolve_target_fqdn,
        )

        domain = (
            target.domain
            or getattr(creds, "target_domain", None)
            or getattr(creds, "domain", None)
        )
        print_info_verbose(f"{self.log_tag}: reading the patch level of {mark_sensitive(target.host, 'host')}")
        target_hostname = _resolve_target_fqdn(target=target, ctx=ctx, domain=domain)

        async def _standard_read() -> OSVersionRead:
            return await self._read(
                host=target.host,
                username=username,
                password=password,
                domain=domain,
                auth_domain=getattr(creds, "auth_domain", None) or domain,
                nt_hash=nt_hash,
                kdc_ip=getattr(creds, "kdc_ip", None),
                target_hostname=target_hostname,
                timeout=self._timeout,
            )

        cache = getattr(ctx, "patch_level", None)
        try:
            if cache is None:
                read = await _standard_read()
            else:
                from adscan_internal.services.cve_scanner.host_patch_level import (  # noqa: PLC0415
                    read_patch_level,
                )

                read = await read_patch_level(
                    cache,
                    host=target.host,
                    target_hostname=target_hostname,
                    standard_principal=str(username),
                    standard_reader=_standard_read,
                    admin_reader=self._admin_read,
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(
                f"{self.log_tag}: patch-level read crashed against "
                f"{mark_sensitive(target.host, 'host')}: {exc}"
            )
            return [_result(target.host, CVEStatus.ERROR, str(exc))]

        status, summary = classify(read)
        payload = {
            "detection_basis": "patch_level",
            "os_build": read.build,
            "os_ubr": read.ubr,
            "os_read_reason": read.reason,
            "read_access": read.access,
            "patch_status": patch_status(read.build, read.ubr),
            "fixed_ubr": DROP_THE_MIC_2_FIXED_UBR_BY_BUILD.get(read.build) if read.build else None,
            "why_no_probe": NO_REMOTE_DISCRIMINATOR,
            "error": read.error,
        }
        return [_result(target.host, status, summary, payload=payload)]


def _result(
    host: str,
    status: CVEStatus,
    summary: str,
    *,
    payload: dict[str, Any] | None = None,
) -> CVEResult:
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=status,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        error=summary if status in (CVEStatus.ERROR, CVEStatus.SKIPPED) else None,
        evidence=Evidence(summary=summary, payload=payload if payload is not None else {"reason": summary}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "DROP_THE_MIC_2_FIXED_UBR_BY_BUILD",
    "FIRST_BUILD_RELEASED_FIXED",
    "NO_REMOTE_DISCRIMINATOR",
    "DropTheMIC2Check",
    "classify",
    "patch_status",
]
