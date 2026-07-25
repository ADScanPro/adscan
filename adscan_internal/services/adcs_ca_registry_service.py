"""ADCS CA-host registry probes (ESC6, ESC11).

Reads the two DWORD values that determine ESC6 / ESC11 indicator state on
the CA host's CertSvc registry hive via aiosmb Remote Registry RPC.

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

# ESC11: IF_ENFORCEENCRYPTICERTREQUEST bit in InterfaceFlags.
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200


@dataclass
class CARegistryProbeResult:
    """Result of probing a CA host's CertSvc registry configuration."""

    target_host: str
    ca_name: str
    success: bool
    editf_attributesubjectaltname2_enabled: bool = False
    enforce_encrypt_icertrequest: bool = False
    edit_flags_raw: int | None = None
    interface_flags_raw: int | None = None
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
            edit_flags, interface_flags = await self._async_read(
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

        result = CARegistryProbeResult(
            target_host=str(target_host),
            ca_name=ca_name,
            success=True,
            editf_attributesubjectaltname2_enabled=bool(
                (edit_flags or 0) & EDITF_ATTRIBUTESUBJECTALTNAME2
            ),
            enforce_encrypt_icertrequest=bool(
                (interface_flags or 0) & IF_ENFORCEENCRYPTICERTREQUEST
            ),
            edit_flags_raw=edit_flags,
            interface_flags_raw=interface_flags,
        )
        print_info_debug(
            "[adcs-ca-probe] registry state resolved: "
            f"target={mark_sensitive(str(target_host), 'host')} "
            f"ca={mark_sensitive(ca_name, 'host')} "
            f"edit_flags={edit_flags!r} interface_flags={interface_flags!r} "
            f"esc6={result.editf_attributesubjectaltname2_enabled} "
            f"esc11_enforced={result.enforce_encrypt_icertrequest}"
        )
        return result

    @staticmethod
    async def _async_read(
        *, config: SMBConfig, ca_name: str
    ) -> tuple[int | None, int | None]:
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
                finally:
                    await rrp.CloseKey(hklm)
        return edit_flags, interface_flags

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
