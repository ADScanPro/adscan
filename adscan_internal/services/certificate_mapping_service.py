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
    """Read DC certificate binding posture using direct Remote Registry RPC."""

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
        from impacket.dcerpc.v5 import rrp, transport  # type: ignore
        from impacket.smbconnection import SMBConnection  # type: ignore

        auth_mode = "kerberos" if use_kerberos else "password"
        connection = None
        dce = None
        try:
            connection = SMBConnection(
                remoteName=target_host,
                remoteHost=target_host,
                sess_port=445,
                timeout=timeout_seconds,
            )
            self._authenticate_connection(
                connection=connection,
                username=username,
                credential=credential,
                auth_domain=auth_domain,
                auth_mode=auth_mode,
                kdc_host=kdc_host,
            )

            rpc_transport = transport.SMBTransport(
                connection.getRemoteName(),  # type: ignore[attr-defined]
                connection.getRemoteHost(),  # type: ignore[attr-defined]
                filename=r"\winreg",
                smb_connection=connection,
            )
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            hklm = rrp.hOpenLocalMachine(dce)["phKey"]
            try:
                strong_binding = self._read_dword_value(
                    dce=dce,
                    root_handle=hklm,
                    registry_path=KDC_REGISTRY_PATH,
                    value_name=STRONG_CERTIFICATE_BINDING_VALUE,
                )
                cert_mapping_methods = self._read_dword_value(
                    dce=dce,
                    root_handle=hklm,
                    registry_path=SCHANNEL_REGISTRY_PATH,
                    value_name=CERTIFICATE_MAPPING_METHODS_VALUE,
                )
            finally:
                try:
                    rrp.hBaseRegCloseKey(dce, hklm)
                except Exception:  # noqa: BLE001
                    pass

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
        finally:
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:  # noqa: BLE001
                    pass
            if connection is not None:
                try:
                    connection.logoff()
                except Exception:  # noqa: BLE001
                    pass

    @staticmethod
    def _read_dword_value(
        *,
        dce: Any,
        root_handle: Any,
        registry_path: str,
        value_name: str,
    ) -> int | None:
        """Read a DWORD value from the remote registry."""
        from impacket.dcerpc.v5 import rrp  # type: ignore

        try:
            key_handle = rrp.hBaseRegOpenKey(dce, root_handle, registry_path)["phkResult"]
        except Exception:
            return None
        try:
            _, value = rrp.hBaseRegQueryValue(dce, key_handle, value_name)
            if isinstance(value, int):
                return int(value)
            return None
        except Exception:
            return None
        finally:
            try:
                rrp.hBaseRegCloseKey(dce, key_handle)
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _authenticate_connection(
        *,
        connection: Any,
        username: str,
        credential: str,
        auth_domain: str,
        auth_mode: str,
        kdc_host: str | None,
    ) -> None:
        """Authenticate an SMB connection for remote registry access."""
        from adscan_internal.services.smb_path_access_service import _looks_like_ntlm_hash

        if auth_mode == "kerberos":
            lmhash = ""
            nthash = ""
            if _looks_like_ntlm_hash(credential):
                if ":" in credential:
                    lmhash, nthash = credential.split(":", 1)
                else:
                    nthash = credential
            connection.kerberosLogin(
                user=username,
                password="" if _looks_like_ntlm_hash(credential) else credential,
                domain=auth_domain,
                lmhash=lmhash,
                nthash=nthash,
                kdcHost=str(kdc_host or "").strip() or None,
                useCache=True,
            )
            return

        if _looks_like_ntlm_hash(credential):
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
            nthash = credential
            if ":" in credential:
                lmhash, nthash = credential.split(":", 1)
            connection.login(
                user=username,
                password="",
                domain=auth_domain,
                lmhash=lmhash,
                nthash=nthash,
            )
            return

        connection.login(
            user=username,
            password=credential,
            domain=auth_domain,
        )
