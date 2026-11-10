"""PrintNightmare (CVE-2021-34527) native check, read-only.

Founder decision 2026-11-06: the check must not change anything on the target,
so it never calls ``RpcAddPrinterDriverEx`` or any other print-spooler add or
install function (the previous probe called the driver-install RPC with an
empty driver and read the error). It reads three facts instead, all over one
authenticated SMB session and all non-state-changing:

1. **Exposure**: the ``spoolss`` named pipe is listed on ``IPC$``, so the Print
   Spooler accepts remote RPC. Absent pipe → ``NOT_APPLICABLE``.
2. **Point and Print policy** (Remote Registry,
   ``HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint``):
   ``RestrictDriverInstallationToAdministrators`` explicitly 0 together with
   ``NoWarningNoElevationOnInstall`` or ``UpdatePromptSettings`` set to 1 lets a
   standard user install a driver without elevation, which Microsoft documents
   as exploitable even on a patched host.
3. **Patch level** (Remote Registry, ``CurrentVersion``): the build and UBR
   against the first revision of each build that carries the July 2021 fix.

Verdict (``classify``):

* insecure Point and Print → ``VULNERABLE`` (inferred, whatever the build);
* build below the fixed revision → ``VULNERABLE`` (inferred);
* fixed build and Point and Print observed at its secure default → ``NOT_VULNERABLE``;
* anything the session could not read (no registry access, a build outside
  the table, a Point and Print key that answered access denied) → ``SKIPPED``,
  NOT ASSESSED. An answer the check cannot interpret never becomes a verdict.

Every VULNERABLE verdict is an INFERENCE (patch level or policy, never an
observed driver load), so the finding is graded High and confirmation-pending
(``adscan_core/reporting/finding_confidence.py``); the runner stamps the band
from the catalog's ``detection_basis``.

Reading HKLM over Remote Registry normally needs local administrator rights on
the target, so a non-admin credential gets "not assessed" on most hosts. That is
the honest result: the patch state was not observed. When ADscan holds an
administrator of the host (Domain Admin, or that host's own local administrator
material), the session is opened with it instead (``ScanContext.patch_level``,
:mod:`..host_patch_level`), and the OS build comes from the run's per-host cache,
so the one read serves every patch-level check. A host first left not assessed
is evaluated again once such a credential exists (``patch_level_rerun``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_exception, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.checks._os_patch_level import (
    ACCESS_ADMINISTRATIVE,
    ACCESS_STANDARD,
    READ_ABSENT,
    READ_DENIED,
    READ_FAILED,
    READ_OK,
    OSVersionRead,
    classify_patch_level,
    coerce_registry_int,
    patch_level_basis,
    read_os_version,
    registry_reason_for,
)
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Evidence,
    Severity,
)

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget


CVE_ID = "CVE-2021-34527"
AKA = "PrintNightmare"
CVSS_V3 = 8.8
# NVD (NIST) and MSRC both publish 8.8 at S:U (not S:C, which computes 9.9).
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

SPOOLSS_PIPE = "spoolss"

POINT_AND_PRINT_PATH = (
    "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint"
)
POINT_AND_PRINT_VALUES = (
    "RestrictDriverInstallationToAdministrators",
    "NoWarningNoElevationOnInstall",
    "UpdatePromptSettings",
)

#: First UBR of each Windows build that carries the July 2021 PrintNightmare fix
#: (the out-of-band updates of 2021-07-06: KB5004950 10240.18969, KB5004948
#: 14393.4470, KB5004949 17134.2208, KB5004947 17763.2029, KB5004946 18363.1646,
#: KB5004945 19041/19042/19043.1083). A build absent from the table is either
#: released after the fix (``FIRST_BUILD_RELEASED_FIXED``) or unknown to the
#: check, and then the patch state is not assessed (Server 2012 / 2012 R2 /
#: 2008 R2 ship monthly rollups this table does not model).
PRINTNIGHTMARE_FIXED_UBR_BY_BUILD: dict[int, int] = {
    10240: 18969,
    14393: 4470,
    17134: 2208,
    17763: 2029,
    18363: 1646,
    19041: 1083,
    19042: 1083,
    19043: 1083,
}
#: Windows 10 21H2 (19044, November 2021) and every later build, Server 2022
#: (20348) included, shipped after the fix.
FIRST_BUILD_RELEASED_FIXED = 19044

# Registry read outcomes (``RegistryRead.reason``), shared with every check
# that reads the patch level (``_os_patch_level``). READ_ABSENT on a Point and
# Print value means the policy default applies.


@dataclass(frozen=True)
class RegistryRead:
    """One registry value read: its integer value, or why it is missing."""

    value: int | None
    reason: str = READ_OK


@dataclass(frozen=True)
class PrintNightmareProbeResult:
    """What the read-only probe observed on one host."""

    #: ``True``/``False`` once the pipe listing completed, ``None`` when it failed.
    spooler_exposed: bool | None
    os_build: int | None = None
    os_ubr: int | None = None
    #: Why the OS version could not be read (``READ_*``), empty when it was.
    os_read_reason: str = READ_OK
    point_and_print: dict[str, RegistryRead] = field(default_factory=dict)
    error: str | None = None
    #: Access of the session that read the Point and Print policy
    #: (``ACCESS_ADMINISTRATIVE`` / ``ACCESS_STANDARD``; empty when unknown).
    session_access: str = ""
    #: Access of the read the OS build came from (it may be another check's).
    os_access: str = ""


ProbeFn = Callable[..., Awaitable[PrintNightmareProbeResult]]
#: Wraps the in-session OS read so the run's cache can serve or record it.
OSReadWrapper = Callable[[Callable[[], Awaitable[OSVersionRead]]], Awaitable[OSVersionRead]]


def _read_basis(access: str) -> str:
    """Evidence clause for a read made with ``access``."""
    return patch_level_basis(OSVersionRead(None, None, access=access))


def patch_status(build: int | None, ubr: int | None) -> str:
    """Classify the host's patch state: ``patched`` / ``unpatched`` / ``unknown``."""
    return classify_patch_level(
        build,
        ubr,
        fixed_ubr_by_build=PRINTNIGHTMARE_FIXED_UBR_BY_BUILD,
        first_build_released_fixed=FIRST_BUILD_RELEASED_FIXED,
    )


def point_and_print_state(values: dict[str, RegistryRead]) -> str:
    """Classify the Point and Print policy: ``insecure`` / ``secure`` / ``unknown``.

    ``insecure`` needs the restriction explicitly lifted (0) AND a prompt
    suppressed (1); that is the configuration Microsoft documents as exploitable
    on a patched host. A key or value that is absent leaves the secure default
    in force. A read that was denied or failed leaves the state unknown.
    """
    if not values:
        return "unknown"
    restrict = values.get("RestrictDriverInstallationToAdministrators")
    no_warning = values.get("NoWarningNoElevationOnInstall")
    update_prompt = values.get("UpdatePromptSettings")
    reads = [r for r in (restrict, no_warning, update_prompt) if r is not None]
    if len(reads) != len(POINT_AND_PRINT_VALUES):
        return "unknown"
    prompt_suppressed = any(
        r.reason == READ_OK and r.value == 1 for r in (no_warning, update_prompt)
    )
    if restrict.reason == READ_OK and restrict.value == 0 and prompt_suppressed:
        return "insecure"
    if any(r.reason in (READ_DENIED, READ_FAILED) for r in reads):
        return "unknown"
    return "secure"


def classify(probe: PrintNightmareProbeResult) -> tuple[CVEStatus, str]:
    """Pure-logic verdict from what the probe observed."""
    if probe.spooler_exposed is None:
        return CVEStatus.SKIPPED, (
            "not assessed: the named pipes could not be listed"
            + (f" ({probe.error})" if probe.error else "")
        )
    if not probe.spooler_exposed:
        return CVEStatus.NOT_APPLICABLE, "Print Spooler not exposed (no spoolss pipe)"
    pnp = point_and_print_state(probe.point_and_print)
    if pnp == "insecure":
        policy_basis = (
            "; inferred from the Point and Print policy, read with administrative access"
            if probe.session_access == ACCESS_ADMINISTRATIVE
            else ""
        )
        return CVEStatus.VULNERABLE, (
            "Print Spooler exposed and Point and Print lets standard users install "
            f"drivers without elevation (exploitable even on a patched host){policy_basis}"
        )
    patch = patch_status(probe.os_build, probe.os_ubr)
    if patch == "unpatched":
        return CVEStatus.VULNERABLE, (
            f"Print Spooler exposed on build {probe.os_build}.{probe.os_ubr}, "
            f"below the July 2021 fix; {_read_basis(probe.os_access)}"
        )
    if patch == "patched" and pnp == "secure":
        return CVEStatus.NOT_VULNERABLE, (
            "Print Spooler exposed, build carries the July 2021 fix and Point and "
            f"Print is at its secure default; {_read_basis(probe.os_access)}"
        )
    reason = probe.os_read_reason if patch == "unknown" else "point_and_print_unreadable"
    return CVEStatus.SKIPPED, (
        "not assessed: Print Spooler exposed but its patch state or Point and "
        f"Print policy could not be read ({reason or 'build not in the fix table'})"
    )


async def _probe_printnightmare(
    *,
    host: str,
    username: str | None,
    password: str | None,
    domain: str | None,
    auth_domain: str | None,
    nt_hash: str | None,
    kdc_ip: str | None,
    target_hostname: str | None = None,
    timeout: int = 30,
    smb_config: Any | None = None,
    os_read_wrapper: OSReadWrapper | None = None,
    session_access: str = "",
) -> PrintNightmareProbeResult:
    """Read-only probe: list pipes, then two registry reads, one SMB session.

    The pipe listing and the registry reads run sequentially on the one
    connection (one aiosmb connection is not safe for concurrent pipes).
    ``smb_config`` (an administrator's session) replaces the scan credential
    when given; ``os_read_wrapper`` lets the run's cache serve the OS build or
    record the one this session reads.
    """
    from adscan_internal.services.smb_transport import (  # noqa: PLC0415
        SMBConfig,
        SMBTransportError,
        smb_machine_with_fallback,
    )

    config = smb_config or SMBConfig(
        target_ip=host,
        target_hostname=target_hostname,
        domain=domain,
        username=username,
        password=password,
        nt_hash=nt_hash,
        auth_domain=auth_domain,
        kdc_ip=kdc_ip,
        timeout=timeout,
    )
    try:
        async with smb_machine_with_fallback(config) as machine:
            pipes: list[str] = []
            async for name, err in machine.list_pipes():
                if err is None and name:
                    pipes.append(str(name))
            exposed = any(p.lower() == SPOOLSS_PIPE for p in pipes)
            if not exposed:
                return PrintNightmareProbeResult(spooler_exposed=False, session_access=session_access)
            os_read, pnp = await _read_registry(
                machine.connection, os_read_wrapper=os_read_wrapper, session_access=session_access
            )
            return PrintNightmareProbeResult(
                spooler_exposed=True,
                os_build=os_read.build,
                os_ubr=os_read.ubr,
                os_read_reason=os_read.reason,
                point_and_print=pnp,
                session_access=session_access,
                os_access=os_read.access,
            )
    except SMBTransportError as exc:
        return PrintNightmareProbeResult(
            spooler_exposed=None, error=f"smb error: {exc}", session_access=session_access
        )


async def _read_registry(
    connection: Any,
    *,
    os_read_wrapper: OSReadWrapper | None = None,
    session_access: str = "",
) -> tuple[OSVersionRead, dict[str, RegistryRead]]:
    """Read the OS build/UBR and the Point and Print values, never writing."""
    from aiosmb.dcerpc.v5.interfaces.remoteregistry import (  # noqa: PLC0415
        HKEY,
        rrprpc_from_smb,
    )

    try:
        async with rrprpc_from_smb(connection) as rrp:
            hklm, err = await rrp.ConnectRegistry(HKEY.LOCAL_MACHINE)
            if err is not None:
                reason = registry_reason_for(err)
                os_read = OSVersionRead(None, None, reason, access=session_access)
                if os_read_wrapper is not None:
                    # Another check may already hold this host's build.
                    os_read = await os_read_wrapper(_constant_read(os_read))
                return os_read, {v: RegistryRead(None, reason) for v in POINT_AND_PRINT_VALUES}
            try:

                async def _in_session() -> OSVersionRead:
                    build, ubr, os_reason = await read_os_version(rrp, hklm)
                    return OSVersionRead(build, ubr, os_reason, access=session_access)

                if os_read_wrapper is not None:
                    os_read = await os_read_wrapper(_in_session)
                else:
                    os_read = await _in_session()
                pnp = await _read_point_and_print(rrp, hklm)
            finally:
                await rrp.CloseKey(hklm)
            return os_read, pnp
    except Exception as exc:  # noqa: BLE001  (Remote Registry unavailable or denied)
        reason = registry_reason_for(exc)
        os_read = OSVersionRead(None, None, reason, access=session_access)
        if os_read_wrapper is not None:
            try:
                os_read = await os_read_wrapper(_constant_read(os_read))
            except Exception:  # noqa: BLE001 - the session failure stands
                pass
        return os_read, {v: RegistryRead(None, reason) for v in POINT_AND_PRINT_VALUES}


def _constant_read(read: OSVersionRead) -> Callable[[], Awaitable[OSVersionRead]]:
    async def _read() -> OSVersionRead:
        return read

    return _read


async def _read_point_and_print(rrp: Any, hklm: Any) -> dict[str, RegistryRead]:
    key, err = await rrp.OpenKey(hklm, POINT_AND_PRINT_PATH)
    if err is not None or key is None:
        reason = registry_reason_for(err)
        return {v: RegistryRead(None, reason) for v in POINT_AND_PRINT_VALUES}
    try:
        out: dict[str, RegistryRead] = {}
        for value in POINT_AND_PRINT_VALUES:
            _vt, data, qerr = await rrp.QueryValue(key, value)
            if qerr is not None:
                out[value] = RegistryRead(None, registry_reason_for(qerr))
            else:
                parsed = coerce_registry_int(data)
                out[value] = RegistryRead(parsed, READ_OK if parsed is not None else READ_ABSENT)
        return out
    finally:
        await rrp.CloseKey(key)


class PrintNightmareCheck:
    """Read-only PrintNightmare exposure check (pipe listing + registry reads)."""

    cve_id: str = CVE_ID
    #: Graded from the host's patch level (and the Point and Print policy): the
    #: post-collection re-run (``patch_level_rerun``) re-evaluates it once
    #: administrator access exists.
    reads_patch_level: bool = True

    def __init__(self, *, probe: ProbeFn | None = None, timeout: int = 30) -> None:
        self._probe = probe or _probe_printnightmare
        self._timeout = timeout

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        """Run the read-only probe against ``target``."""
        if creds is None:
            return [_result(target.host, CVEStatus.ERROR, "PrintNightmare probe requires authentication")]

        from adscan_internal.services.cve_scanner.checks.webdav import (  # noqa: PLC0415
            _resolve_target_fqdn,
        )

        domain = (
            target.domain
            or getattr(creds, "target_domain", None)
            or getattr(creds, "domain", None)
        )
        print_info_verbose(f"[printnightmare] probing {mark_sensitive(target.host, 'host')}")
        target_hostname = _resolve_target_fqdn(target=target, ctx=ctx, domain=domain)
        base_kwargs: dict[str, Any] = {
            "host": target.host,
            "username": getattr(creds, "username", None),
            "password": getattr(creds, "password", None),
            "domain": domain,
            "auth_domain": getattr(creds, "auth_domain", None) or domain,
            "nt_hash": getattr(creds, "nt_hash", None),
            "kdc_ip": getattr(creds, "kdc_ip", None),
            "target_hostname": target_hostname,
            "timeout": self._timeout,
        }
        try:
            cache = getattr(ctx, "patch_level", None)
            if cache is None:
                probe = await self._probe(**base_kwargs)
            else:
                probe = await self._probe_with_cache(
                    cache,
                    base_kwargs,
                    host=target.host,
                    target_hostname=target_hostname,
                    standard_principal=str(getattr(creds, "username", "") or ""),
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[printnightmare] probe crashed against {target.host}: {exc}")
            return [_result(target.host, CVEStatus.ERROR, str(exc))]

        status, summary = classify(probe)
        payload = {
            "detection_basis": "patch_level",
            "spooler_exposed": probe.spooler_exposed,
            "os_build": probe.os_build,
            "os_ubr": probe.os_ubr,
            "os_read_reason": probe.os_read_reason,
            "patch_status": patch_status(probe.os_build, probe.os_ubr),
            "point_and_print": {
                name: {"value": read.value, "reason": read.reason}
                for name, read in probe.point_and_print.items()
            },
            "point_and_print_state": point_and_print_state(probe.point_and_print),
            "read_access": probe.session_access,
            "os_read_access": probe.os_access,
            "error": probe.error,
        }
        return [_result(target.host, status, summary, payload=payload)]

    async def _probe_with_cache(
        self,
        cache: Any,
        base_kwargs: dict[str, Any],
        *,
        host: str,
        target_hostname: str | None,
        standard_principal: str,
    ) -> PrintNightmareProbeResult:
        """Probe with an administrator's session when one exists, else the scan credential.

        The OS build goes through the run's cache, so a build another check
        already read is reused and the one read here serves the others.
        """
        def _wrapper(access: str, principal: str) -> OSReadWrapper:
            async def _wrap(reader: Callable[[], Awaitable[OSVersionRead]]) -> OSVersionRead:
                return await cache.get_or_read(
                    host, target_hostname, access=access, principal=principal, reader=reader
                )

            return _wrap

        access = await cache.resolve_access(host, target_hostname)
        if access is not None:
            probe = await self._probe(
                **base_kwargs,
                smb_config=access.config,
                session_access=ACCESS_ADMINISTRATIVE,
                os_read_wrapper=_wrapper(ACCESS_ADMINISTRATIVE, access.principal),
            )
            if probe.spooler_exposed is not None:
                return probe
            # The administrator's session itself failed: the scan credential
            # still gets its own attempt below.
        return await self._probe(
            **base_kwargs,
            session_access=ACCESS_STANDARD,
            os_read_wrapper=_wrapper(ACCESS_STANDARD, standard_principal),
        )


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
        evidence=Evidence(summary=summary, payload=payload or {}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "FIRST_BUILD_RELEASED_FIXED",
    "POINT_AND_PRINT_VALUES",
    "PRINTNIGHTMARE_FIXED_UBR_BY_BUILD",
    "PrintNightmareCheck",
    "PrintNightmareProbeResult",
    "RegistryRead",
    "classify",
    "patch_status",
    "point_and_print_state",
]
