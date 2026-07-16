"""Network discovery helpers for ADscan.

This module centralises small, reusable pieces of network discovery logic that
were previously embedded in the monolithic ``adscan.py`` shell implementation.

The goal is to keep the heavy lifting here so CLI/interactive code can remain
thin wrappers while still preserving legacy behaviour.
"""

from __future__ import annotations

from typing import Any, Protocol
import asyncio
import secrets
import socket
import struct
import time

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info_debug,
    print_info_verbose,
)
from adscan_internal.services.async_bridge import run_async_sync


class NetworkDiscoveryHost(Protocol):
    """Host interface required by the network discovery helpers."""

    def run_command(self, command: str, **kwargs):  # noqa: ANN001
        ...

    netexec_path: str | None


async def _infer_domain_from_smb_native(
    dc_ip: str,
    *,
    port: int = 445,
    timeout: int = 8,
) -> tuple[str | None, str | None]:
    """Infer domain FQDN and hostname from the SMB NTLM challenge (Type 2).

    Native aiosmb replacement for ``nxc smb <ip>``: an unauthenticated SMB2
    negotiate followed by a single ``session_setup(fake_auth=True)`` round-trip
    yields the server's NTLM CHALLENGE, whose AV_PAIR target info carries the
    DNS domain name, DNS/NetBIOS computer name and NetBIOS domain — exactly the
    fields nxc parses from its login banner. ``fake_auth`` returns as soon as the
    challenge is received, so no credential is ever validated.

    Returns ``(domain_fqdn, hostname)`` or ``(None, None)`` on failure. Only a
    dotted FQDN is returned as the domain (matching the legacy nxc contract).
    """
    try:
        from aiosmb.commons.connection.factory import SMBConnectionFactory
    except ImportError:
        return None, None

    # Guest/anonymous URL: the factory wires an NTLM gssapi so session_setup can
    # process the server challenge. No real credential is sent (fake_auth).
    url = f"smb+ntlm-password://WORKGROUP\\guest:@{dc_ip}:{port}"
    info: dict | None = None
    try:
        factory = SMBConnectionFactory.from_url(url)
        conn = factory.get_connection()
        try:
            _, err = await asyncio.wait_for(conn.connect(), timeout=timeout)
            if err is not None:
                return None, None
            # A normal SMB2 negotiate (NOT protocol_test=True, which selects the
            # SMBv1 wildcard dialect and leaves session_setup unusable).
            res, err = await asyncio.wait_for(conn.negotiate(), timeout=timeout)
            if not res or err is not None:
                return None, None
            ok, err = await asyncio.wait_for(
                conn.session_setup(fake_auth=True), timeout=timeout
            )
            if not ok or err is not None:
                return None, None
            info = conn.get_extra_info()
        finally:
            try:
                await conn.disconnect()
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[smb_infer] native SMB banner probe failed: {exc}")
        return None, None

    ntlm_data = info.get("ntlm_data") if isinstance(info, dict) else None
    if not isinstance(ntlm_data, dict):
        return None, None

    domain = str(ntlm_data.get("dnsdomainname") or "").strip().rstrip(".").lower() or None
    hostname = (
        str(ntlm_data.get("dnscomputername") or "").strip().rstrip(".")
        or str(ntlm_data.get("computername") or "").strip()
    ) or None

    # Match the nxc contract: only a dotted FQDN counts as a domain.
    if domain:
        if domain in {"workgroup", "unknown"} or "." not in domain:
            domain = None

    if domain:
        print_info_debug(
            f"[smb_infer] native NTLM challenge ({dc_ip}): "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"host={mark_sensitive(hostname or 'N/A', 'hostname')}"
        )
    return domain, hostname


def _nc_to_fqdn(nc: str) -> str | None:
    """Convert an LDAP distinguishedName base to a dotted FQDN.

    ``"DC=ais,DC=local"``  →  ``"ais.local"``
    Returns ``None`` when *nc* contains no DC components.
    """
    parts = [
        seg[3:]
        for seg in nc.replace(" ", "").split(",")
        if seg[:3].upper() == "DC=" and seg[3:]
    ]
    return ".".join(parts).lower() if parts else None


def _domain_hostname_from_rootdse_info(
    server_info: dict,
) -> tuple[str | None, str | None]:
    """Extract ``(domain_fqdn, dc_hostname)`` from a bound client's rootDSE info.

    Shared by the anonymous and authenticated rootDSE readers so the
    ``defaultNamingContext`` / ``dnsHostName`` parsing lives in exactly one
    place.
    """
    # defaultNamingContext → "DC=ais,DC=local" → "ais.local"
    raw_nc = server_info.get("defaultNamingContext")
    if not raw_nc:
        raw_nc = (server_info.get("namingContexts") or [None])[0]
    nc_str = str(raw_nc[0] if isinstance(raw_nc, list) else raw_nc).strip() if raw_nc else ""
    domain = _nc_to_fqdn(nc_str) if nc_str else None

    # dnsHostName → "dc01.ais.local"
    raw_host = server_info.get("dnsHostName")
    hostname: str | None = None
    if raw_host:
        hostname = str(raw_host[0] if isinstance(raw_host, list) else raw_host).strip() or None
    return domain, hostname


async def _infer_domain_from_ldap_authenticated(
    dc_ip: str,
    *,
    username: str,
    password: str,
    timeout: int = 8,
) -> tuple[str | None, str | None]:
    """Infer domain FQDN and hostname from an AUTHENTICATED LDAP rootDSE read.

    Fallback used only when the anonymous rootDSE read failed — the common
    case on a hardened DC that disables anonymous LDAP/SMB — and the operator
    already supplied credentials for the target moments earlier (e.g.
    ``start_auth`` -> "I know only a DC/DNS IP"). Binding with those
    credentials recovers ``defaultNamingContext``/``dnsHostName`` instead of
    dead-ending to manual domain entry despite holding valid creds.

    An NTLM bind is used deliberately: it needs no domain context, which is
    exactly the piece being discovered here (a Kerberos bind would need the
    realm upfront). Goes through the mandatory LDAPS->LDAP fallback SSOT
    (``async_connect_with_ldap_fallback``) — never a direct badldap factory
    call. Best-effort and bounded to ``timeout`` seconds (this is a domain-
    identity probe, not a full scan): any failure returns ``(None, None)`` so
    the caller falls through to the existing PTR / manual-entry recovery; it
    never raises.
    """
    try:
        from adscan_internal.services.ldap_transport_service import (
            ADscanLDAPConfig,
            async_connect_with_ldap_fallback,
        )
    except ImportError:
        return None, None

    config = ADscanLDAPConfig(
        domain="",
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=username,
        password=password,
    )

    client: Any = None
    try:
        # Outer hard ceiling on the whole confidentiality ladder (LDAPS ->
        # StartTLS -> SASL sign+seal -> cleartext) — this is a domain-identity
        # probe, not a full scan, so it must fail fast rather than hang.
        # Mirrors the bounded posture-probe LDAP binds in posture_probe.py.
        client, used_ldaps = await asyncio.wait_for(
            async_connect_with_ldap_fallback(config), timeout=timeout
        )

        server_info: dict | None = None
        if hasattr(client, "get_server_info"):
            server_info = client.get_server_info()
        if not isinstance(server_info, dict):
            server_info = getattr(client, "_serverinfo", None)
        if not isinstance(server_info, dict):
            return None, None

        domain, hostname = _domain_hostname_from_rootdse_info(server_info)
        if domain:
            transport = "LDAPS" if used_ldaps else "LDAP"
            print_info_debug(
                f"[ldap_infer] authenticated rootDSE ({transport} {dc_ip}): "
                f"domain={mark_sensitive(domain, 'domain')} "
                f"host={mark_sensitive(hostname or 'N/A', 'hostname')}"
            )
            return domain, hostname
        return None, None
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[ldap_infer] authenticated LDAP probe failed: {exc}")
        return None, None
    finally:
        if client is not None:
            try:
                disconnect = getattr(client, "disconnect", None)
                if disconnect is not None:
                    maybe = disconnect()
                    if asyncio.iscoroutine(maybe):
                        await maybe
            except Exception:  # noqa: BLE001
                pass


async def _infer_domain_from_ldap_native(
    dc_ip: str,
    *,
    timeout: int = 8,
    credential: tuple[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """Infer domain FQDN and hostname from an anonymous LDAP rootDSE read.

    Tries LDAPS (636) first, then plain LDAP (389). Reads ``defaultNamingContext``
    for the domain and ``dnsHostName`` for the hostname — both attributes are
    always returned in the rootDSE from Windows DCs, even with anonymous access.

    When the anonymous read fails AND ``credential`` (``(username, password)``)
    is supplied, retries once with an AUTHENTICATED rootDSE read (see
    :func:`_infer_domain_from_ldap_authenticated`) before giving up — a
    hardened DC that blocks anonymous LDAP still answers a bind the operator
    already holds valid creds for. Anonymous-first stays the default: no
    credential is sent unless the anonymous attempt already failed.

    Returns ``(domain_fqdn, hostname)`` or ``(None, None)`` on failure.

    This is the sole implementation behind ``infer_domain_from_ldap_banner``;
    the legacy ``nxc ldap -u '' -p ''`` subprocess fallback was removed.
    """
    try:
        from adscan_internal.services.ldap_transport_service import (
            async_anonymous_ldap_connection,
        )
    except ImportError:
        return None, None

    try:
        # Centralized anonymous SIMPLE-bind with LDAPS->LDAP fallback. badldap
        # fetches the rootDSE attributes during connect, so the bound client's
        # _serverinfo already carries defaultNamingContext + dnsHostName — no
        # explicit search is needed.
        async with async_anonymous_ldap_connection(
            dc_ip, timeout=timeout
        ) as (client, used_ldaps):
            server_info: dict | None = None
            if hasattr(client, "get_server_info"):
                server_info = client.get_server_info()
            if not isinstance(server_info, dict):
                server_info = getattr(client, "_serverinfo", None)
            if not isinstance(server_info, dict):
                server_info = None

            domain, hostname = (
                _domain_hostname_from_rootdse_info(server_info)
                if server_info
                else (None, None)
            )

            if domain:
                transport = "LDAPS" if used_ldaps else "LDAP"
                print_info_debug(
                    f"[ldap_infer] native rootDSE ({transport} {dc_ip}): "
                    f"domain={mark_sensitive(domain, 'domain')} "
                    f"host={mark_sensitive(hostname or 'N/A', 'hostname')}"
                )
                return domain, hostname
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[ldap_infer] native LDAP anonymous probe failed: {exc}")

    # Anonymous inference failed (blocked, or answered with no naming context).
    # Only retry authenticated when the operator already supplied credentials
    # for THIS probe — never send credentials speculatively.
    if credential:
        username, password = credential
        if username and password is not None:
            return await _infer_domain_from_ldap_authenticated(
                dc_ip, username=username, password=password, timeout=timeout
            )

    return None, None


def infer_domain_from_smb_banner(
    host: NetworkDiscoveryHost,
    *,
    target_ip: str,
    timeout_seconds: int = 60,
    attempts: int = 3,
    retry_delay_seconds: float = 1.0,
) -> tuple[str | None, str | None]:
    """Infer a domain (FQDN) and hostname from a target IP via native SMB.

    Reads the server's NTLM CHALLENGE target info (DNS domain, DNS/NetBIOS
    computer name) via an aiosmb negotiate + ``fake_auth`` session-setup — the
    same data nxc surfaces from its SMB login banner, with no subprocess. Falls
    back to a native NBSTAT (UDP/137) query for the NetBIOS hostname when the
    challenge does not expose a computer name.

    Args:
        host: Retained for signature compatibility with the DNS candidate flow.
        target_ip: Target host IP address (DC/DNS candidate).
        timeout_seconds: Overall probe budget; the native SMB probe caps its own
            per-round-trip timeout at ≤8s for fast failure.
        attempts: Number of native probe attempts when nothing is returned.
        retry_delay_seconds: Delay between attempts.

    Returns:
        Tuple of (domain_fqdn, hostname). Values are ``None`` when inference fails.
    """
    _ = host  # native probe needs no shell/run_command context
    ip_clean = (target_ip or "").strip()
    if not ip_clean:
        return None, None

    native_timeout = min(timeout_seconds, 8)
    domain: str | None = None
    hostname: str | None = None
    for attempt in range(1, max(attempts, 1) + 1):
        try:
            domain, hostname = run_async_sync(
                _infer_domain_from_smb_native(ip_clean, timeout=native_timeout)
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[smb_infer] native SMB path raised unexpectedly: {exc}")
            domain, hostname = None, None
        if domain or hostname:
            break
        if attempt < max(attempts, 1):
            time.sleep(retry_delay_seconds)

    # NBSTAT fallback for the NetBIOS hostname when the challenge lacked one.
    if not hostname:
        hostname = _query_netbios_name_native(ip_clean)

    return domain, hostname


def infer_domain_from_ldap_banner(
    host: NetworkDiscoveryHost,
    *,
    target_ip: str,
    timeout_seconds: int = 60,
    attempts: int = 3,
    retry_delay_seconds: float = 1.0,
    credential: tuple[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """Infer a domain (FQDN) and DC hostname from a target IP via native LDAP.

    Performs an anonymous rootDSE read (native badldap, no subprocess): reads
    ``defaultNamingContext`` for the domain and ``dnsHostName`` for the DC
    hostname. Covers the DCs where port 389 or 636 is reachable.

    Args:
        credential: Optional ``(username, password)`` already captured for
            this scan (e.g. an authenticated ``start_auth`` flow). Only used
            as a RETRY when the anonymous rootDSE read fails — a hardened DC
            that disables anonymous LDAP still answers a bind the operator
            already holds valid credentials for, instead of dead-ending to
            manual domain entry. ``None`` (default) preserves the
            anonymous-only legacy behaviour.

    Returns ``(domain_fqdn, hostname)`` or ``(None, None)`` when the probe fails.
    """
    _ = (host, attempts, retry_delay_seconds)  # retained for signature compat
    ip_clean = (target_ip or "").strip()
    if not ip_clean:
        return None, None

    # Native path — anonymous LDAP bind → rootDSE (defaultNamingContext + dnsHostName),
    # authenticated retry when creds are available and anonymous failed.
    # Uses a short timeout (≤8s) so it fails fast when LDAP is not available.
    native_timeout = min(timeout_seconds, 8)
    try:
        return run_async_sync(
            _infer_domain_from_ldap_native(
                ip_clean, timeout=native_timeout, credential=credential
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[ldap_infer] native path raised unexpectedly: {exc}")
        return None, None


def _encode_nbns_name(name: str = "*") -> bytes:
    """Encode a NetBIOS name in the wire format used by NBNS (RFC 1002).

    The wildcard ``*`` is used for NBSTAT (node status) queries: it's padded
    with NULs to 16 bytes and each nibble is encoded as an ASCII letter
    ('A'..'P'), producing a 32-byte label prefixed with 0x20 and terminated
    with 0x00.
    """
    raw = name.encode("ascii")[:16].ljust(16, b"\x00")
    encoded = bytearray()
    for byte in raw:
        encoded.append(0x41 + (byte >> 4))
        encoded.append(0x41 + (byte & 0x0F))
    return bytes([0x20]) + bytes(encoded) + b"\x00"


def _query_netbios_name_native(
    target_ip: str,
    *,
    timeout: float = 3.0,
    retries: int = 2,
) -> str | None:
    """Query the NetBIOS workgroup/domain name of a host via NBSTAT (UDP/137).

    This replaces the legacy ``nmblookup -A`` subprocess with a self-contained
    UDP query. Returns the NetBIOS domain/workgroup name (suffix 0x00 with the
    group bit set), or ``None`` if the host does not respond or no group name
    is reported.
    """
    target = (target_ip or "").strip()
    if not target:
        return None

    txn_id = secrets.randbits(16)
    header = struct.pack(">HHHHHH", txn_id, 0x0000, 1, 0, 0, 0)
    question = _encode_nbns_name("*") + struct.pack(">HH", 0x0021, 0x0001)
    packet = header + question

    last_exc: Exception | None = None
    for _ in range(max(retries, 1)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(packet, (target, 137))
            data, _ = sock.recvfrom(4096)
        except (socket.timeout, OSError) as exc:
            last_exc = exc
            continue
        finally:
            sock.close()

        # Skip 12-byte header + question (encoded name 34 bytes + qtype 2 + qclass 2)
        offset = 12 + 34 + 4
        # Answer: name (compressed pointer 2B or full 34B), type(2), class(2), ttl(4), rdlength(2)
        if offset >= len(data):
            continue
        if data[offset] & 0xC0:
            offset += 2
        else:
            offset += 34
        offset += 2 + 2 + 4 + 2  # type, class, ttl, rdlength
        if offset >= len(data):
            continue
        num_names = data[offset]
        offset += 1

        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name_bytes = data[offset:offset + 15].rstrip(b" \x00")
            suffix = data[offset + 15]
            flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
            offset += 18
            # Domain/workgroup: suffix 0x00 with group bit set (0x8000)
            if suffix == 0x00 and (flags & 0x8000):
                try:
                    return name_bytes.decode("ascii", errors="replace").strip()
                except Exception:  # noqa: BLE001
                    return None
        return None

    if last_exc is not None:
        print_info_debug(f"NBSTAT query to {mark_sensitive(target, 'ip')} failed: {last_exc}")
    return None


def extract_netbios(
    host: NetworkDiscoveryHost,
    domain: str,
    *,
    dc_ip: str | None = None,
) -> str | None:
    """Extract the NetBIOS name for a domain using a native NBSTAT (UDP/137) query.

    Resolution order:
    1. Native NBSTAT query against the DC IP (``dc_ip`` argument, or
       ``host.pdc`` / first entry of ``host.dcs`` as fallback).
    2. First label of the FQDN, upper-cased.

    Args:
        host: Object providing host context (``pdc`` / ``dcs`` attributes).
        domain: Domain name from which to derive NetBIOS.
        dc_ip: Optional explicit DC IP to query.

    Returns:
        The extracted or derived NetBIOS name, or ``None`` on unrecoverable error.
    """
    try:
        marked_domain = mark_sensitive(domain, "domain")
        domain_clean = (domain or "").strip()
        if not domain_clean:
            return None

        ip_candidate = (dc_ip or "").strip() or (getattr(host, "pdc", "") or "").strip()
        if not ip_candidate:
            dcs = getattr(host, "dcs", None) or []
            if dcs:
                ip_candidate = (dcs[0] or "").strip()

        if ip_candidate:
            netbios = _query_netbios_name_native(ip_candidate)
            if netbios:
                return netbios
            print_info_debug(
                f"NBSTAT did not return a domain/workgroup name for {mark_sensitive(ip_candidate, 'ip')}."
            )
        else:
            print_info_debug("No DC IP available for NBSTAT query; falling back to FQDN label.")

        netbios_default = domain_clean.split(".")[0].upper()
        marked_netbios_default = mark_sensitive(netbios_default, "domain")
        print_info_verbose(
            f"Could not extract NetBIOS from domain {marked_domain}, using {marked_netbios_default} as default."
        )
        return netbios_default
    except Exception as exc:  # noqa: BLE001 - preserve legacy catch-all semantics
        telemetry.capture_exception(exc)
        print_error("Error extracting NetBIOS.")
        print_exception(show_locals=False, exception=exc)
        return None
