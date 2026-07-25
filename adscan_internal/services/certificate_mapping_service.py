"""Resolve DC certificate binding and Schannel mapping posture.

This service reads registry-backed settings from a domain controller when
Remote Registry is reachable with the provided authentication context.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.smb_transport import (
    SMBConfig,
    _looks_like_nt_hash,
    run_smb_operation,
    smb_machine_for,
)
from adscan_core.rich_output import print_exception


KDC_REGISTRY_PATH = r"SYSTEM\CurrentControlSet\Services\Kdc"
SCHANNEL_REGISTRY_PATH = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"

STRONG_CERTIFICATE_BINDING_VALUE = "StrongCertificateBindingEnforcement"
CERTIFICATE_MAPPING_METHODS_VALUE = "CertificateMappingMethods"


@dataclass(frozen=True, slots=True)
class CertificateBindingState:
    """Registry-backed certificate binding posture for one DC."""

    target_host: str
    auth_mode: str
    success: bool
    strong_certificate_binding_enforcement: int | None = None
    certificate_mapping_methods: int | None = None
    error_message: str | None = None

    @property
    def strong_binding_enforced(self) -> bool | None:
        """Return ``True`` only when the DC explicitly enforces strong binding."""
        if self.strong_certificate_binding_enforcement is None:
            return None
        return int(self.strong_certificate_binding_enforcement) >= 2


class CertificateMappingService(BaseService):
    """Read DC certificate binding posture using aiosmb Remote Registry RPC."""

    def read_dc_binding_state(
        self,
        *,
        target_host: str,
        username: str,
        credential: str,
        auth_domain: str,
        use_kerberos: bool,
        kdc_host: str | None = None,
        timeout_seconds: int = 10,
    ) -> CertificateBindingState:
        """Return the binding posture for one DC, or ``success=False`` when unknown."""
        auth_mode = "kerberos" if use_kerberos else "password"

        is_hash = _looks_like_nt_hash(credential)
        config = SMBConfig(
            target_ip=target_host,
            target_hostname=target_host,
            domain=auth_domain,
            auth_domain=auth_domain,
            username=username,
            password=None if is_hash else credential,
            nt_hash=credential if is_hash else None,
            kdc_ip=str(kdc_host or "").strip() or None,
            timeout=timeout_seconds,
            use_kerberos=use_kerberos,
        )

        try:
            strong_binding, cert_mapping_methods = run_smb_operation(
                self._async_read_registry(config)
            )
            state = CertificateBindingState(
                target_host=target_host,
                auth_mode=auth_mode,
                success=True,
                strong_certificate_binding_enforcement=strong_binding,
                certificate_mapping_methods=cert_mapping_methods,
            )
            print_info_debug(
                "[cert-binding] registry state resolved: "
                f"target={mark_sensitive(target_host, 'host')} "
                f"auth_mode={auth_mode} "
                f"strong_binding={state.strong_certificate_binding_enforcement!r} "
                f"cert_mapping_methods={state.certificate_mapping_methods!r}"
            )
            return state
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            error_text = f"{type(exc).__name__}: {exc}"
            print_info_debug(
                "[cert-binding] registry state unavailable: "
                f"target={mark_sensitive(target_host, 'host')} "
                f"auth_mode={auth_mode} "
                f"error={error_text}"
            )
            return CertificateBindingState(
                target_host=target_host,
                auth_mode=auth_mode,
                success=False,
                error_message=error_text,
            )

    @staticmethod
    async def _async_read_registry(
        config: SMBConfig,
    ) -> tuple[int | None, int | None]:
        """Open an aiosmb Remote Registry session and read the two DWORD values."""
        from aiosmb.dcerpc.v5.interfaces.remoteregistry import HKEY, rrprpc_from_smb

        async with smb_machine_for(config) as machine:
            async with rrprpc_from_smb(machine.connection) as rrp:
                hklm, err = await rrp.ConnectRegistry(HKEY.LOCAL_MACHINE)
                if err is not None:
                    raise err

                strong_binding = await CertificateMappingService._read_dword_via_rrp(
                    rrp=rrp,
                    root_handle=hklm,
                    registry_path=KDC_REGISTRY_PATH,
                    value_name=STRONG_CERTIFICATE_BINDING_VALUE,
                )
                cert_mapping_methods = (
                    await CertificateMappingService._read_dword_via_rrp(
                        rrp=rrp,
                        root_handle=hklm,
                        registry_path=SCHANNEL_REGISTRY_PATH,
                        value_name=CERTIFICATE_MAPPING_METHODS_VALUE,
                    )
                )
                await rrp.CloseKey(hklm)

        return strong_binding, cert_mapping_methods

    @staticmethod
    async def _read_dword_via_rrp(
        *,
        rrp: Any,
        root_handle: Any,
        registry_path: str,
        value_name: str,
    ) -> int | None:
        """Read a DWORD value from the remote registry via aiosmb RRPRPC.

        Returns the integer value or ``None`` when the key or value is absent.
        """
        key_handle, err = await rrp.OpenKey(root_handle, registry_path)
        if err is not None or key_handle is None:
            return None
        try:
            _val_type, value, err = await rrp.QueryValue(key_handle, value_name)
            if err is not None or value is None:
                return None
            if isinstance(value, int):
                return int(value)
            return None
        finally:
            await rrp.CloseKey(key_handle)

