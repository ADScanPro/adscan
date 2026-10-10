"""ADCS CA-host registry probes (ESC6, ESC11, Certighost).

Reads the DWORD values that determine ESC6 / ESC11 indicator state on the CA
host's CertSvc registry hive via aiosmb Remote Registry RPC, PLUS the CA host's
OS build / UBR (Update Build Revision) needed for the Certighost
(CVE-2026-54121) patch-level check. All reads share one SMB session.

Best-effort: probe failures degrade to ``success=False`` with all flags
``False`` so detectors emit no edges and no false positives slip through.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core.rich_output import print_info_debug
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.smb_transport import SMBConfig, smb_machine_for
from adscan_core.rich_output import print_exception

# ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 bit in EditFlags.
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

# Certighost (CVE-2026-54121): EDITF_ENABLECHASECLIENTDC bit in EditFlags. When
# set, the CA "chase" fallback contacts a requester-supplied DC without
# verifying it is a real DC, enabling the DC-impersonation certificate avenue.
EDITF_ENABLECHASECLIENTDC = 0x00100000

# ESC11: IF_ENFORCEENCRYPTICERTREQUEST bit in InterfaceFlags.
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200

# OS CurrentVersion registry key — carries the build number and UBR used for the
# Certighost patch-level decision. ``CurrentBuildNumber`` is a REG_SZ, ``UBR`` a
# REG_DWORD (present on Windows 10 / Server 2016 and later).
_CURRENT_VERSION_PATH = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"


@dataclass
class CARegistryProbeResult:
    """Result of probing a CA host's CertSvc registry configuration."""

    target_host: str
    ca_name: str
    success: bool
    editf_attributesubjectaltname2_enabled: bool = False
    editf_enablechaseclientdc_enabled: bool = False
    enforce_encrypt_icertrequest: bool = False
    edit_flags_raw: int | None = None
    interface_flags_raw: int | None = None
    # True when the registry session reached the CA's CertSvc configuration and
    # the EditFlags value was readable (even if a particular bit is unset). The
    # Certighost detector requires this before trusting the chase bit; a failed
    # read stays UNKNOWN rather than becoming a false negative.
    edit_flags_readable: bool = False
    # CA host OS build / UBR (Certighost patch-level check). ``None`` when the
    # OS CurrentVersion key could not be read — the detector then degrades to
    # UNKNOWN rather than fabricating a patched/unpatched verdict.
    os_build_number: int | None = None
    os_ubr: int | None = None
    os_major_version: int | None = None
    os_minor_version: int | None = None
    error_message: str | None = None


class ADCSCARegistryProbe:
    """Probe a CA host for ESC6 and ESC11 indicator registry values.

    Reads two DWORD values under
    ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CAName>``:

    - ``EditFlags`` (ESC6 — ``EDITF_ATTRIBUTESUBJECTALTNAME2`` bit)
    - ``InterfaceFlags`` (ESC11 — ``IF_ENFORCEENCRYPTICERTREQUEST`` bit)

    A single SMB session performs both reads.
    """

    async def probe(self, *, config: SMBConfig, ca_name: str) -> CARegistryProbeResult:
        target_host = (
            getattr(config, "target_hostname", None)
            or getattr(config, "target_ip", None)
            or ""
        )
        try:
            edit_flags, interface_flags, os_version = await self._async_read(
                config=config, ca_name=ca_name
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                "[adcs-ca-probe] registry read failed: "
                f"target={mark_sensitive(str(target_host), 'host')} "
                f"ca={mark_sensitive(ca_name, 'host')} "
                f"error={type(exc).__name__}: {exc}"
            )
            return CARegistryProbeResult(
                target_host=str(target_host),
                ca_name=ca_name,
                success=False,
                error_message=f"{type(exc).__name__}: {exc}",
            )

        build_number, ubr, major, minor = os_version
        result = CARegistryProbeResult(
            target_host=str(target_host),
            ca_name=ca_name,
            success=True,
            editf_attributesubjectaltname2_enabled=bool(
                (edit_flags or 0) & EDITF_ATTRIBUTESUBJECTALTNAME2
            ),
            editf_enablechaseclientdc_enabled=bool(
                (edit_flags or 0) & EDITF_ENABLECHASECLIENTDC
            ),
            enforce_encrypt_icertrequest=bool(
                (interface_flags or 0) & IF_ENFORCEENCRYPTICERTREQUEST
            ),
            edit_flags_raw=edit_flags,
            interface_flags_raw=interface_flags,
            edit_flags_readable=edit_flags is not None,
            os_build_number=build_number,
            os_ubr=ubr,
            os_major_version=major,
            os_minor_version=minor,
        )
        print_info_debug(
            "[adcs-ca-probe] registry state resolved: "
            f"target={mark_sensitive(str(target_host), 'host')} "
            f"ca={mark_sensitive(ca_name, 'host')} "
            f"edit_flags={edit_flags!r} interface_flags={interface_flags!r} "
            f"esc6={result.editf_attributesubjectaltname2_enabled} "
            f"esc11_enforced={result.enforce_encrypt_icertrequest} "
            f"certighost_chase={result.editf_enablechaseclientdc_enabled} "
            f"os_build={build_number!r} os_ubr={ubr!r}"
        )
        return result

    @staticmethod
    async def _async_read(
        *, config: SMBConfig, ca_name: str
    ) -> tuple[
        int | None,
        int | None,
        tuple[int | None, int | None, int | None, int | None],
    ]:
        from aiosmb.dcerpc.v5.interfaces.remoteregistry import HKEY, rrprpc_from_smb

        registry_path = (
            f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}"
        )

        async with smb_machine_for(config) as machine:
            async with rrprpc_from_smb(machine.connection) as rrp:
                hklm, err = await rrp.ConnectRegistry(HKEY.LOCAL_MACHINE)
                if err is not None:
                    raise err
                try:
                    edit_flags = await ADCSCARegistryProbe._read_dword(
                        rrp=rrp,
                        root_handle=hklm,
                        path=registry_path,
                        value="EditFlags",
                    )
                    interface_flags = await ADCSCARegistryProbe._read_dword(
                        rrp=rrp,
                        root_handle=hklm,
                        path=registry_path,
                        value="InterfaceFlags",
                    )
                    # OS build / UBR for the Certighost patch-level check. Best-
                    # effort over the SAME session: a missing OS key leaves the
                    # build/UBR None and the detector degrades to UNKNOWN.
                    os_version = await ADCSCARegistryProbe._read_os_version(
                        rrp=rrp, root_handle=hklm
                    )
                finally:
                    await rrp.CloseKey(hklm)
        return edit_flags, interface_flags, os_version

    @staticmethod
    async def _read_os_version(
        *, rrp: Any, root_handle: Any
    ) -> tuple[int | None, int | None, int | None, int | None]:
        """Read (build, UBR, major, minor) from the OS CurrentVersion key.

        ``CurrentBuildNumber`` is a REG_SZ (e.g. ``"20348"``); ``UBR`` and the
        major/minor version numbers are REG_DWORDs (present on Windows 10 /
        Server 2016+). Any unreadable value degrades to ``None`` so the
        Certighost patch-level decision stays honest (UNKNOWN, never a false
        patched/unpatched verdict).
        """
        key_handle, err = await rrp.OpenKey(root_handle, _CURRENT_VERSION_PATH)
        if err is not None or key_handle is None:
            return (None, None, None, None)
        try:
            build = ADCSCARegistryProbe._coerce_int(
                await ADCSCARegistryProbe._read_value(
                    rrp=rrp, key_handle=key_handle, value="CurrentBuildNumber"
                )
            )
            ubr = ADCSCARegistryProbe._coerce_int(
                await ADCSCARegistryProbe._read_value(
                    rrp=rrp, key_handle=key_handle, value="UBR"
                )
            )
            major = ADCSCARegistryProbe._coerce_int(
                await ADCSCARegistryProbe._read_value(
                    rrp=rrp,
                    key_handle=key_handle,
                    value="CurrentMajorVersionNumber",
                )
            )
            minor = ADCSCARegistryProbe._coerce_int(
                await ADCSCARegistryProbe._read_value(
                    rrp=rrp,
                    key_handle=key_handle,
                    value="CurrentMinorVersionNumber",
                )
            )
            return (build, ubr, major, minor)
        finally:
            await rrp.CloseKey(key_handle)

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        """Coerce a REG_SZ / REG_DWORD value to int, else ``None``."""
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return int(value)
        if isinstance(value, str):
            text = value.strip().rstrip("\x00").strip()
            if text.isdigit():
                return int(text)
        return None

    @staticmethod
    async def _read_value(*, rrp: Any, key_handle: Any, value: str) -> Any:
        """Return a registry value's raw data (int or str), or ``None``."""
        _val_type, value_data, err = await rrp.QueryValue(key_handle, value)
        if err is not None:
            return None
        return value_data

    @staticmethod
    async def _read_dword(
        *, rrp: Any, root_handle: Any, path: str, value: str
    ) -> int | None:
        key_handle, err = await rrp.OpenKey(root_handle, path)
        if err is not None or key_handle is None:
            return None
        try:
            _val_type, value_data, err = await rrp.QueryValue(key_handle, value)
            if err is not None or value_data is None:
                return None
            if isinstance(value_data, int):
                return int(value_data)
            return None
        finally:
            await rrp.CloseKey(key_handle)
