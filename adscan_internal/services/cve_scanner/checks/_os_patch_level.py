"""Shared OS patch-level reading for the CVE checks that infer from build and UBR.

Some CVEs have no non-disruptive network observable that tells a patched host
from an unpatched one. For those the check reads the host's patch level instead:
``CurrentBuildNumber`` and ``UBR`` (update build revision) under
``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`` over Remote Registry,
and compares the revision with the first one of that build that carries the fix.

That key is readable without administrator rights on a default server: it is
listed in ``winreg\\AllowedExactPaths``, which lets an authenticated user read it
remotely even where the rest of HKLM is closed. A host where Remote Registry is
stopped or the read is denied stays "not assessed", never a verdict.

A verdict built on this reading is an INFERENCE (the fix is assumed present
because its update is installed), so the catalog grades such a check
``detection_basis="inferred"``.

In practice a scan run as an ordinary user still gets "not assessed" on most
hosts: a hardened ``SecurePipeServers\\winreg`` ACL or a trimmed
``AllowedExactPaths`` list denies the read, and an administrator of the host is
what reliably gets it. Every read records WHICH access produced it
(``OSVersionRead.access``), and the evidence line of a verdict built on an
administrative read says so. The per-host cache that makes
one read serve every patch-level check, and the credential choice, live in
``cve_scanner.host_patch_level``.

Consumers: PrintNightmare (CVE-2021-34527) and Drop the MIC 2 (CVE-2019-1166).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

# Registry read outcomes (``reason``).
READ_OK = ""
READ_ABSENT = "absent"  # key or value not present
READ_DENIED = "access_denied"
READ_FAILED = "read_failed"

PATCHED = "patched"
UNPATCHED = "unpatched"
UNKNOWN = "unknown"

CURRENT_VERSION_PATH = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

#: Which access produced a read (``OSVersionRead.access``).
ACCESS_ADMINISTRATIVE = "administrative"
ACCESS_STANDARD = "standard"


@dataclass(frozen=True)
class OSVersionRead:
    """The build and UBR one host reported, or why they could not be read."""

    build: int | None
    ubr: int | None
    #: ``READ_*``; empty when the build was read.
    reason: str = READ_OK
    #: Transport error text when the session itself failed.
    error: str | None = None
    #: ``ACCESS_ADMINISTRATIVE`` / ``ACCESS_STANDARD``; empty when unknown.
    access: str = ""


def patch_level_basis(read: OSVersionRead) -> str:
    """The evidence clause for a verdict inferred from ``read``.

    Client-facing: it ends the evidence line of every patch-level verdict, so it
    names how the patch level was obtained and nothing internal.
    """
    if read.access == ACCESS_ADMINISTRATIVE:
        return "inferred from the patch level, read with administrative access"
    return "inferred from the patch level"


def classify_patch_level(
    build: int | None,
    ubr: int | None,
    *,
    fixed_ubr_by_build: Mapping[int, int],
    first_build_released_fixed: int,
) -> str:
    """Return ``patched`` / ``unpatched`` / ``unknown`` for one host.

    Args:
        build: ``CurrentBuildNumber`` read from the host.
        ubr: ``UBR`` read from the host.
        fixed_ubr_by_build: first UBR of each build that carries the fix.
        first_build_released_fixed: every build at or above this one shipped
            after the fix.

    A build outside the table and below ``first_build_released_fixed`` (the
    6.x builds serviced by monthly rollups, pre-release builds) is ``unknown``:
    the check does not model it, so it never becomes a verdict.
    """
    if build is None:
        return UNKNOWN
    if int(build) >= first_build_released_fixed:
        return PATCHED
    threshold = fixed_ubr_by_build.get(int(build))
    if threshold is None or ubr is None:
        return UNKNOWN
    return PATCHED if int(ubr) >= threshold else UNPATCHED


async def read_os_version(rrp: Any, hklm: Any) -> tuple[int | None, int | None, str]:
    """Read ``CurrentBuildNumber`` and ``UBR`` on an open HKLM handle, never writing."""
    key, err = await rrp.OpenKey(hklm, CURRENT_VERSION_PATH)
    if err is not None or key is None:
        return None, None, registry_reason_for(err)
    try:
        build = coerce_registry_int(await _query(rrp, key, "CurrentBuildNumber"))
        ubr = coerce_registry_int(await _query(rrp, key, "UBR"))
    finally:
        await rrp.CloseKey(key)
    return build, ubr, READ_OK if build is not None else READ_FAILED


async def read_os_version_over_smb(
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
) -> OSVersionRead:
    """Open one authenticated SMB session and read the OS build and UBR.

    Goes through ``smb_machine_with_fallback`` (posture-aware, Kerberos first
    when the domain requires it), so the read works where NTLM is disabled. The
    only operations are ``OpenKey`` / ``QueryValue`` / ``CloseKey``.
    """
    from adscan_internal.services.smb_transport import SMBConfig  # noqa: PLC0415

    config = SMBConfig(
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
    return await read_os_version_with_config(config)


async def read_os_version_with_config(config: Any) -> OSVersionRead:
    """Read the OS build and UBR over one SMB session built from ``config``.

    ``config`` is an ``SMBConfig`` (a resolved administrator credential, or the
    scan credential). The only operations are ``OpenKey`` / ``QueryValue`` /
    ``CloseKey``; nothing is written.
    """
    from adscan_internal.services.smb_transport import (  # noqa: PLC0415
        SMBTransportError,
        smb_machine_with_fallback,
    )

    try:
        async with smb_machine_with_fallback(config) as machine:
            return await _read_os_version_on_connection(machine.connection)
    except SMBTransportError as exc:
        return OSVersionRead(None, None, READ_FAILED, error=f"smb error: {exc}")


async def _read_os_version_on_connection(connection: Any) -> OSVersionRead:
    from aiosmb.dcerpc.v5.interfaces.remoteregistry import (  # noqa: PLC0415
        HKEY,
        rrprpc_from_smb,
    )

    try:
        async with rrprpc_from_smb(connection) as rrp:
            hklm, err = await rrp.ConnectRegistry(HKEY.LOCAL_MACHINE)
            if err is not None:
                return OSVersionRead(None, None, registry_reason_for(err))
            try:
                build, ubr, reason = await read_os_version(rrp, hklm)
            finally:
                await rrp.CloseKey(hklm)
            return OSVersionRead(build, ubr, reason)
    except Exception as exc:  # noqa: BLE001  (Remote Registry unavailable or denied)
        return OSVersionRead(None, None, registry_reason_for(exc))


async def _query(rrp: Any, key: Any, value: str) -> Any:
    _vt, data, err = await rrp.QueryValue(key, value)
    return None if err is not None else data


def registry_reason_for(err: Any) -> str:
    """Map a registry error to a ``READ_*`` reason (2 = not found, 5 = denied)."""
    if err is None:
        return READ_ABSENT
    code = getattr(err, "errno", None)
    if code == 2:
        return READ_ABSENT
    if code == 5:
        return READ_DENIED
    return READ_FAILED


def coerce_registry_int(value: Any) -> int | None:
    """A REG_DWORD or a numeric REG_SZ as ``int``; anything else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        text = value.strip().rstrip("\x00").strip()
        if text.isdigit():
            return int(text)
    return None


__all__ = [
    "ACCESS_ADMINISTRATIVE",
    "ACCESS_STANDARD",
    "CURRENT_VERSION_PATH",
    "OSVersionRead",
    "PATCHED",
    "READ_ABSENT",
    "READ_DENIED",
    "READ_FAILED",
    "READ_OK",
    "UNKNOWN",
    "UNPATCHED",
    "classify_patch_level",
    "coerce_registry_int",
    "patch_level_basis",
    "read_os_version",
    "read_os_version_over_smb",
    "read_os_version_with_config",
    "registry_reason_for",
]
