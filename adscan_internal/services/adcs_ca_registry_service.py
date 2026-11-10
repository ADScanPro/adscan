"""ADCS CA-host registry probes (ESC6, ESC11, Certighost).

Reads the DWORD values that determine ESC6 / ESC11 indicator state on the CA
host's CertSvc registry hive via aiosmb Remote Registry RPC, PLUS the CA host's
OS build / UBR (Update Build Revision) needed for the Certighost
(CVE-2026-54121) patch-level check. All reads share one SMB session.

Where Windows keeps each value (the probe reads each one from THAT key)
-----------------------------------------------------------------------
Root: ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>``.

* ``InterfaceFlags`` (ESC11, ``IF_ENFORCEENCRYPTICERTREQUEST``) is a CA
  property: it lives on the CA root key. ``certutil -setreg CA\\InterfaceFlags``
  writes it there, and Certipy's ``get_config_rrp`` reads it there.
* ``EditFlags`` (ESC6 ``EDITF_ATTRIBUTESUBJECTALTNAME2`` and Certighost
  ``EDITF_ENABLECHASECLIENTDC``) is a setting of the POLICY MODULE, not of the
  CA: it lives under ``<root>\\PolicyModules\\<active module>``, where the
  active module is named by the ``Active`` value of ``<root>\\PolicyModules``
  (``CertificateAuthority_MicrosoftDefault.Policy`` on a default install).
  Every ``EDITF_*`` flag is the policy module's (certpol.h); Microsoft's own
  remediation for ESC6 is ``certutil -setreg policy\\EditFlags
  -EDITF_ATTRIBUTESUBJECTALTNAME2``, where ``policy\\`` resolves to that key, and
  Certipy reads ``EditFlags`` from ``PolicyModules\\<Active>`` the same way.
  Reading it from the CA root found nothing on a real CA (the value is absent
  there), which left ESC6 and Certighost not assessed on every probed CA.

Best-effort: probe failures degrade to ``success=False`` with all flags
``False`` so detectors emit no edges and no false positives slip through.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core.rich_output import print_info_debug
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.adcs.esc12_detection import (
    REASON_ACCESS_DENIED,
    REASON_CA_CONFIG_NOT_FOUND,
    REASON_READ_FAILED,
    classify_registry_error,
)
from adscan_internal.services.smb_transport import SMBConfig, smb_machine_with_fallback
from adscan_core.rich_output import print_exception

# A value that is simply absent under an otherwise readable key.
REASON_VALUE_NOT_PRESENT = "registry_value_not_present"

_ERROR_FILE_NOT_FOUND = 0x2
_ERROR_ACCESS_DENIED = 0x5

# ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 bit in EditFlags.
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

# Certighost (CVE-2026-54121): EDITF_ENABLECHASECLIENTDC bit in EditFlags. When
# set, the CA "chase" fallback contacts a requester-supplied DC without
# verifying it is a real DC, enabling the DC-impersonation certificate avenue.
EDITF_ENABLECHASECLIENTDC = 0x00100000

# ESC11: IF_ENFORCEENCRYPTICERTREQUEST bit in InterfaceFlags.
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200

# Policy module resolution (EditFlags lives under the ACTIVE policy module).
_POLICY_MODULES_SUBKEY = "PolicyModules"
_ACTIVE_POLICY_VALUE = "Active"
# Windows' own default module name. Used only when the ``Active`` value is
# absent from a readable ``PolicyModules`` key, never when the key itself could
# not be read (that stays a data gap).
DEFAULT_POLICY_MODULE = "CertificateAuthority_MicrosoftDefault.Policy"

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
    # Same contract for ``InterfaceFlags`` (ESC11). An unreadable value is NOT
    # "encryption not enforced": the collector keeps ESC11 silent and records the
    # check as not assessed, so a read that did not complete never raises ESC11.
    interface_flags_readable: bool = False
    # Stable ``not_checked`` reason (``esc12_detection.REASON_*``) when the
    # session failed or a value could not be read; empty when both flag reads
    # completed. Feeds the observation record for ESC6 / ESC11 / Certighost.
    error_reason: str = ""
    # CA host OS build / UBR (Certighost patch-level check). ``None`` when the
    # OS CurrentVersion key could not be read — the detector then degrades to
    # UNKNOWN rather than fabricating a patched/unpatched verdict.
    os_build_number: int | None = None
    os_ubr: int | None = None
    os_major_version: int | None = None
    os_minor_version: int | None = None
    # The policy module ``EditFlags`` was read from (diagnostic; empty when the
    # module could not be resolved).
    policy_module: str = ""
    error_message: str | None = None


class ADCSCARegistryProbe:
    """Probe a CA host for ESC6 / ESC11 / Certighost indicator registry values.

    Under ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CAName>``:

    - ``InterfaceFlags`` on the CA root key (ESC11, ``IF_ENFORCEENCRYPTICERTREQUEST``)
    - ``EditFlags`` on ``PolicyModules\\<Active>`` (ESC6
      ``EDITF_ATTRIBUTESUBJECTALTNAME2``, Certighost ``EDITF_ENABLECHASECLIENTDC``)

    A single SMB session performs every read (see the module docstring for the
    reference of each location).
    """

    async def probe(self, *, config: SMBConfig, ca_name: str) -> CARegistryProbeResult:
        target_host = (
            getattr(config, "target_hostname", None)
            or getattr(config, "target_ip", None)
            or ""
        )
        try:
            (
                edit_flags,
                interface_flags,
                os_version,
                read_reasons,
                policy_module,
            ) = await self._async_read(config=config, ca_name=ca_name)
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
                error_reason=classify_registry_error(exc),
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
            interface_flags_readable=interface_flags is not None,
            error_reason=(
                ""
                if edit_flags is not None and interface_flags is not None
                else (read_reasons.get("EditFlags") or read_reasons.get("InterfaceFlags") or REASON_READ_FAILED)
            ),
            os_build_number=build_number,
            os_ubr=ubr,
            os_major_version=major,
            os_minor_version=minor,
            policy_module=policy_module,
        )
        print_info_debug(
            "[adcs-ca-probe] registry state resolved: "
            f"target={mark_sensitive(str(target_host), 'host')} "
            f"ca={mark_sensitive(ca_name, 'host')} "
            f"policy_module={policy_module or '-'} "
            f"edit_flags={edit_flags!r} interface_flags={interface_flags!r} "
            f"edit_flags_reason={read_reasons.get('EditFlags') or '-'} "
            f"interface_flags_reason={read_reasons.get('InterfaceFlags') or '-'} "
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
        dict[str, str],
        str,
    ]:
        from aiosmb.dcerpc.v5.interfaces.remoteregistry import HKEY, rrprpc_from_smb

        ca_root = ca_configuration_path(ca_name)

        async with smb_machine_with_fallback(config) as machine:
            async with rrprpc_from_smb(machine.connection) as rrp:
                hklm, err = await rrp.ConnectRegistry(HKEY.LOCAL_MACHINE)
                if err is not None:
                    raise err
                try:
                    reasons: dict[str, str] = {}
                    # ESC11: a CA property, on the CA root key.
                    (
                        interface_flags,
                        reasons["InterfaceFlags"],
                    ) = await ADCSCARegistryProbe._read_dword(
                        rrp=rrp,
                        root_handle=hklm,
                        path=ca_root,
                        value="InterfaceFlags",
                    )
                    # ESC6 / Certighost: a policy-module setting, on the ACTIVE
                    # policy module's key.
                    policy_module, module_reason = await ADCSCARegistryProbe._resolve_policy_module(
                        rrp=rrp, root_handle=hklm, ca_root=ca_root
                    )
                    if policy_module:
                        edit_flags, reasons["EditFlags"] = await ADCSCARegistryProbe._read_dword(
                            rrp=rrp,
                            root_handle=hklm,
                            path=policy_module_path(ca_name, policy_module),
                            value="EditFlags",
                        )
                    else:
                        edit_flags, reasons["EditFlags"] = None, module_reason
                    # OS build / UBR for the Certighost patch-level check. Best-
                    # effort over the SAME session: a missing OS key leaves the
                    # build/UBR None and the detector degrades to UNKNOWN.
                    os_version = await ADCSCARegistryProbe._read_os_version(
                        rrp=rrp, root_handle=hklm
                    )
                finally:
                    await rrp.CloseKey(hklm)
        return edit_flags, interface_flags, os_version, reasons, policy_module

    @staticmethod
    async def _resolve_policy_module(
        *, rrp: Any, root_handle: Any, ca_root: str
    ) -> tuple[str, str]:
        """Return ``(active policy module name, reason)``.

        The name comes from the ``Active`` value of ``<ca_root>\\PolicyModules``.
        When that key is readable and the ``Active`` value is absent or empty,
        the Windows default module is used (the module a default install creates
        and activates). When the key cannot be opened, or ``Active`` cannot be
        read (denied, failed), the name is empty and the reason says why:
        ``EditFlags`` then stays NOT ASSESSED, never read from a key Windows may
        not be consulting.
        """
        modules_path = f"{ca_root}\\{_POLICY_MODULES_SUBKEY}"
        key_handle, err = await rrp.OpenKey(root_handle, modules_path)
        if err is not None or key_handle is None:
            return "", _open_failure_reason(err)
        try:
            _val_type, value_data, err = await rrp.QueryValue(key_handle, _ACTIVE_POLICY_VALUE)
            if err is not None and _errno_of(err) != _ERROR_FILE_NOT_FOUND:
                # Denied or failed: which module is active is UNKNOWN, so no
                # key is guessed (a custom module's flags are not the default's).
                return "", _value_failure_reason(err)
            name = _registry_string(value_data) if err is None else ""
            return (name or DEFAULT_POLICY_MODULE), ""
        finally:
            await rrp.CloseKey(key_handle)

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
    ) -> tuple[int | None, str]:
        """Return ``(value, reason)``; ``reason`` is empty when the read completed.

        An unreadable value is reported with the reason it could not be read
        (key missing, access denied, value absent, other failure) so the caller
        never confuses "could not read" with "flag not set".
        """
        key_handle, err = await rrp.OpenKey(root_handle, path)
        if err is not None or key_handle is None:
            return None, _open_failure_reason(err)
        try:
            _val_type, value_data, err = await rrp.QueryValue(key_handle, value)
            if err is not None:
                return None, _value_failure_reason(err)
            if value_data is None:
                return None, REASON_VALUE_NOT_PRESENT
            if isinstance(value_data, int) and not isinstance(value_data, bool):
                return int(value_data), ""
            return None, REASON_READ_FAILED
        finally:
            await rrp.CloseKey(key_handle)


def ca_configuration_path(ca_name: str) -> str:
    """The CA root key: ``SYSTEM\\...\\CertSvc\\Configuration\\<CA>`` (``InterfaceFlags``)."""
    return f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}"


def policy_module_path(ca_name: str, policy_module: str) -> str:
    """The active policy module's key, where Windows keeps ``EditFlags``."""
    return f"{ca_configuration_path(ca_name)}\\{_POLICY_MODULES_SUBKEY}\\{policy_module}"


def _registry_string(value: Any) -> str:
    """Return a REG_SZ / REG_MULTI_SZ value as one clean name, ``""`` otherwise."""
    if isinstance(value, (list, tuple)):
        for item in value:
            text = _registry_string(item)
            if text:
                return text
        return ""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-16-le")
        except UnicodeDecodeError:
            return ""
    if not isinstance(value, str):
        return ""
    return value.replace("\x00", "").strip()


def _errno_of(err: Any) -> int | None:
    value = getattr(err, "errno", None)
    return int(value) if isinstance(value, int) else None


def _open_failure_reason(err: Any) -> str:
    """Map a failed ``OpenKey`` to a stable ``not_checked`` reason."""
    code = _errno_of(err)
    if code == _ERROR_ACCESS_DENIED:
        return REASON_ACCESS_DENIED
    if code == _ERROR_FILE_NOT_FOUND:
        return REASON_CA_CONFIG_NOT_FOUND
    return REASON_READ_FAILED if err is not None else REASON_CA_CONFIG_NOT_FOUND


def _value_failure_reason(err: Any) -> str:
    """Map a failed ``QueryValue`` to a stable ``not_checked`` reason."""
    code = _errno_of(err)
    if code == _ERROR_ACCESS_DENIED:
        return REASON_ACCESS_DENIED
    if code == _ERROR_FILE_NOT_FOUND:
        return REASON_VALUE_NOT_PRESENT
    return REASON_READ_FAILED
