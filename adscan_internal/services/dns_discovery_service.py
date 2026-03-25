"""DNS discovery service for ADscan.

This module extracts the DNS discovery helpers from the monolithic `adscan.py`.
It is intentionally focused on discovery primitives used across multiple flows:

- SRV record discovery via direct DNS queries
- IPv4 address resolution with layered resolver fallbacks
- PDC discovery via a specific resolver with UDP→TCP fallback

The service is CLI-friendly: it uses `adscan_internal.rich_output` for debug
messages and centralizes DNS transport through dnspython instead of shelling out
to external CLI resolvers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
import ipaddress
import re
import socket
import time

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.reversename
import dns.rdatatype

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error_context,
    print_info_debug,
    print_info_verbose,
    print_exception,
    print_warning,
    print_warning_debug,
)


class _DNSDiscoveryHost(Protocol):
    """Host interface required by DNSDiscoveryService."""

    def run_command(self, command: str, **kwargs):  # noqa: ANN001
        ...


@dataclass(frozen=True)
class DNSDiscoveryRuntime:
    """Runtime configuration and helpers for DNSDiscoveryService."""

    dig_compat_flags: str


@dataclass(frozen=True)
class DNSQueryResult:
    """Structured DNS query result used internally by the discovery service."""

    answers: list[str]
    error: str | None = None
    rcode: str | None = None


def is_dns_resolution_error(error_output: str) -> bool:
    """Return True if output indicates a DNS resolution failure."""
    normalized = (error_output or "").lower()
    return any(
        needle in normalized
        for needle in (
            "could not resolve host",
            "temporary failure in name resolution",
            "name resolution",
            "nodename nor servname provided",
        )
    )


def is_host_resolvable(hostname: str, *, timeout_seconds: int = 6) -> bool:
    """Return True if the system can resolve a hostname using the current resolver."""
    hostname = (hostname or "").strip()
    if not hostname:
        return False
    try:
        socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        return True
    except Exception:
        return False


def _is_loopback_ip(value: str) -> bool:
    """Return True if value is a loopback IP address."""
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _is_private_or_loopback_ip(value: str) -> bool:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(parsed.is_private or parsed.is_loopback)


def _is_valid_ipv4(value: str) -> bool:
    """Return True when value is a syntactically valid IPv4 address."""
    candidate = str(value or "").strip()
    if not candidate:
        return False
    try:
        return ipaddress.ip_address(candidate).version == 4
    except ValueError:
        return False


def choose_preferred_pdc_ip(
    ip_candidates: list[str],
    *,
    preferred_ips: list[str | None] | None = None,
    reference_ip: str | None = None,
) -> str | None:
    """Select the best IP from DNS answers, preferring known PDC addresses.

    Args:
        ip_candidates: List of IP addresses from DNS resolution
        preferred_ips: List of preferred IPs (e.g., known PDC IPs) in priority order
        reference_ip: Reference IP to match subnet (first two octets)

    Returns:
        Selected IP address or None if no valid candidate
    """
    if not ip_candidates:
        if preferred_ips:
            for pref in preferred_ips:
                if pref and _is_valid_ipv4(pref):
                    return pref
        return None

    normalized: list[str] = []
    for ip_val in ip_candidates:
        if ip_val and _is_valid_ipv4(ip_val) and ip_val not in normalized:
            normalized.append(ip_val)

    if not normalized:
        if preferred_ips:
            for pref in preferred_ips:
                if pref and _is_valid_ipv4(pref):
                    return pref
        return None

    fallback_pref: str | None = None
    if preferred_ips:
        for pref in preferred_ips:
            if not pref or not _is_valid_ipv4(pref):
                continue
            if pref in normalized:
                return pref
            if fallback_pref is None:
                fallback_pref = pref

    if reference_ip and _is_valid_ipv4(reference_ip):
        ref_parts = reference_ip.split(".")
        for candidate in normalized:
            cand_parts = candidate.split(".")
            if len(ref_parts) >= 2 and len(cand_parts) >= 2:
                if cand_parts[:2] == ref_parts[:2]:
                    return candidate

    for candidate in normalized:
        if not _is_loopback_ip(candidate):
            return candidate

    if fallback_pref:
        return fallback_pref

    return normalized[0]


def preflight_install_dns(
    hostnames: list[str],
    *,
    attempts: int = 3,
    backoff_seconds: int = 3,
    context_label: str = "network preflight",
) -> bool:
    """Ensure required hostnames can be resolved before running git/pip installs."""
    hostnames = [name.strip() for name in hostnames if name and name.strip()]
    if not hostnames:
        return True

    for attempt in range(1, attempts + 1):
        failed = [name for name in hostnames if not is_host_resolvable(name)]
        if not failed:
            return True
        if attempt < attempts:
            wait_s = backoff_seconds * attempt
            print_warning(
                f"{context_label}: DNS resolution failed for {', '.join(failed)}; "
                f"retrying ({attempt}/{attempts}) in {wait_s}s..."
            )
            time.sleep(wait_s)
            continue

    print_error_context(
        "DNS resolution is not working for required install hosts.",
        context={"hosts": ", ".join(hostnames)},
        suggestions=[
            "Check /etc/resolv.conf (nameserver entries)",
            f"Verify DNS: getent hosts {hostnames[0]}",
            "If you're on a VPN/lab, ensure public DNS resolution works (GitHub/PyPI) or configure a working resolver",
            "Then re-run: adscan install --verbose",
        ],
        show_exception=False,
        exception=None,
    )
    return False


class DNSDiscoveryService:
    """DNS discovery helpers used by domain/collector workflows."""

    def __init__(self, host: _DNSDiscoveryHost, runtime: DNSDiscoveryRuntime):
        self._host = host
        self._rt = runtime

    def _resolve_query_nameservers(self, resolver: str | None) -> list[str]:
        """Return resolver IPs to use for a DNS query in priority order."""
        if resolver:
            return [resolver]
        return self._get_resolv_conf_nameservers(include_loopback=True)

    def _extract_dns_answers(
        self,
        response: dns.message.Message,
        *,
        rdtype: str,
    ) -> list[str]:
        """Extract normalized answers from a dnspython response."""
        normalized_rdtype = rdtype.upper()
        answers: list[str] = []

        for rrset in response.answer:
            if dns.rdatatype.to_text(rrset.rdtype).upper() != normalized_rdtype:
                continue
            for item in rrset:
                if normalized_rdtype == "SRV":
                    value = item.target.to_text().rstrip(".")
                elif normalized_rdtype == "A":
                    value = item.address
                elif normalized_rdtype == "PTR":
                    value = item.target.to_text().rstrip(".")
                else:
                    value = item.to_text().strip()
                if value and value not in answers:
                    answers.append(value)

        return answers

    def _query_dns_records(
        self,
        *,
        qname: str,
        rdtype: str,
        resolver: str | None = None,
        tcp: bool = False,
        timeout_seconds: int = 2,
        tries: int = 1,
        checking_disabled: bool = False,
    ) -> DNSQueryResult:
        """Query DNS records directly with dnspython and return structured results."""
        normalized_qname = (qname or "").strip().rstrip(".")
        if not normalized_qname:
            return DNSQueryResult(answers=[], error="invalid_name")

        try:
            query_name = dns.name.from_text(normalized_qname)
        except Exception:
            return DNSQueryResult(answers=[], error="invalid_name")

        try:
            rdtype_value = dns.rdatatype.from_text(rdtype.upper())
        except Exception:
            return DNSQueryResult(answers=[], error="invalid_type")

        nameservers = self._resolve_query_nameservers(resolver)
        if not nameservers:
            return DNSQueryResult(answers=[], error="no_servers")

        last_error: str | None = "no_servers"
        last_rcode: str | None = None

        for nameserver in nameservers:
            if not nameserver:
                continue
            marked_nameserver = mark_sensitive(nameserver, "ip")
            for _attempt in range(max(1, tries)):
                try:
                    message = dns.message.make_query(
                        query_name,
                        rdtype_value,
                        use_edns=False,
                    )
                    if checking_disabled:
                        message.flags |= dns.flags.CD

                    if tcp:
                        response = dns.query.tcp(
                            message,
                            where=nameserver,
                            timeout=timeout_seconds,
                        )
                    else:
                        response = dns.query.udp(
                            message,
                            where=nameserver,
                            timeout=timeout_seconds,
                            ignore_unexpected=True,
                        )
                except dns.exception.Timeout:
                    last_error = "timeout"
                    continue
                except OSError as exc:
                    last_error = "no_servers"
                    print_info_debug(
                        f"[dns] Query transport failure via {marked_nameserver}: {exc}"
                    )
                    continue
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    last_error = "command_failed"
                    print_info_debug(
                        f"[dns] Query failure for {mark_sensitive(normalized_qname, 'domain')} "
                        f"via {marked_nameserver}: {exc}"
                    )
                    continue

                rcode_text = dns.rcode.to_text(response.rcode()).lower()
                last_rcode = rcode_text
                if response.rcode() == dns.rcode.NOERROR:
                    return DNSQueryResult(
                        answers=self._extract_dns_answers(response, rdtype=rdtype),
                        error=None,
                        rcode=rcode_text,
                    )
                if response.rcode() == dns.rcode.NXDOMAIN:
                    return DNSQueryResult(
                        answers=[],
                        error="nxdomain",
                        rcode=rcode_text,
                    )
                if response.rcode() == dns.rcode.SERVFAIL:
                    return DNSQueryResult(
                        answers=[],
                        error="servfail",
                        rcode=rcode_text,
                    )
                if response.rcode() == dns.rcode.REFUSED:
                    return DNSQueryResult(
                        answers=[],
                        error="refused",
                        rcode=rcode_text,
                    )
                return DNSQueryResult(
                    answers=[],
                    error=f"rcode_{rcode_text}",
                    rcode=rcode_text,
                )

        return DNSQueryResult(answers=[], error=last_error, rcode=last_rcode)

    def dig_srv_records(
        self,
        *,
        srv_name: str,
        resolver: str | None = None,
        tcp: bool = False,
        timeout_seconds: int = 2,
        tries: int = 1,
    ) -> tuple[list[str], str | None]:
        """Query SRV records and return target hostnames."""
        normalized_srv = (srv_name or "").strip().rstrip(".")
        if not normalized_srv:
            return [], "invalid_srv_name"
        query_result = self._query_dns_records(
            qname=normalized_srv,
            rdtype="SRV",
            resolver=resolver,
            tcp=tcp,
            timeout_seconds=timeout_seconds,
            tries=tries,
        )
        if query_result.error == "invalid_name":
            return [], "invalid_srv_name"
        if query_result.error in {"timeout", "no_servers"}:
            return [], "no_servers"
        if query_result.error == "command_failed":
            return [], "command_failed"
        return query_result.answers, None

    def dig_srv_records_robust(
        self,
        *,
        srv_name: str,
        resolver: str | None = None,
        tcp: bool = False,
        timeout_seconds: int = 2,
        tries: int = 1,
        allow_fallback: bool = True,
    ) -> tuple[list[str], str | None]:
        """Query SRV records with layered resolver fallbacks."""
        targets, err = self.dig_srv_records(
            srv_name=srv_name,
            resolver=resolver,
            tcp=tcp,
            timeout_seconds=timeout_seconds,
            tries=tries,
        )
        if targets:
            print_info_debug("[dns] dig_srv_records_robust used primary resolver")
            return targets, err

        if not tcp:
            targets_tcp, err_tcp = self.dig_srv_records(
                srv_name=srv_name,
                resolver=resolver,
                tcp=True,
                timeout_seconds=timeout_seconds,
                tries=tries,
            )
            if targets_tcp:
                print_info_debug("[dns] dig_srv_records_robust used TCP fallback")
                return targets_tcp, err_tcp
            if err is None:
                err = err_tcp

        if not allow_fallback:
            return [], err

        if self._should_try_systemd_stub_resolver():
            targets, err = self.dig_srv_records(
                srv_name=srv_name,
                resolver="127.0.0.53",
                tcp=tcp,
                timeout_seconds=timeout_seconds,
                tries=tries,
            )
            if targets:
                print_info_debug(
                    "[dns] dig_srv_records_robust used systemd-resolved stub"
                )
                return targets, err

        get_resolv_nameservers = getattr(self, "_get_resolv_conf_nameservers", None)
        if not callable(get_resolv_nameservers):
            print_info_debug(
                "[dns] dig_srv_records_robust: resolv.conf nameserver check unavailable in this runtime"
            )
            return [], err

        attempted_resolvers: list[str] = []
        for ns in get_resolv_nameservers(include_loopback=False):
            if not ns:
                continue
            if resolver and ns == resolver:
                continue
            attempted_resolvers.append(ns)
            targets, err = self.dig_srv_records(
                srv_name=srv_name,
                resolver=ns,
                tcp=tcp,
                timeout_seconds=timeout_seconds,
                tries=tries,
            )
            if targets:
                print_info_debug(
                    f"[dns] dig_srv_records_robust used resolver {mark_sensitive(ns, 'ip')}"
                )
                return targets, err

        if attempted_resolvers:
            marked = [mark_sensitive(ns, "ip") for ns in attempted_resolvers]
            print_info_debug(
                f"[dns] dig_srv_records_robust exhausted resolver fallbacks: {marked}"
            )

        return [], err
    def resolve_ipv4_addresses(
        self,
        fqdn: str,
        resolver: str | None = None,
        *,
        tcp: bool = False,
    ) -> list[str]:
        """Resolve IPv4 addresses for a hostname via direct DNS queries."""
        marked_fqdn = mark_sensitive(fqdn, "domain")
        print_info_debug(
            f"[_resolve_ipv4_addresses] Resolving IPv4 for FQDN: {marked_fqdn}, resolver: {resolver}"
        )
        query_result = self._query_dns_records(
            qname=fqdn,
            rdtype="A",
            resolver=resolver,
            tcp=tcp,
            timeout_seconds=30,
            tries=1,
        )
        candidates = [
            candidate
            for candidate in query_result.answers
            if candidate and _is_valid_ipv4(candidate) and not _is_loopback_ip(candidate)
        ]

        candidates = [
            c for c in candidates if c and _is_valid_ipv4(c) and not _is_loopback_ip(c)
        ]
        candidates = list(dict.fromkeys(candidates))
        print_info_debug(
            f"[_resolve_ipv4_addresses] Final IP candidates for {marked_fqdn}: {candidates}"
        )
        return candidates

    def resolve_ipv4_addresses_robust(
        self,
        fqdn: str,
        resolver: str | None = None,
        *,
        tcp: bool = False,
    ) -> list[str]:
        """Resolve IPv4 addresses for a hostname with layered fallbacks."""
        candidates = self.resolve_ipv4_addresses(fqdn, resolver=resolver, tcp=tcp)
        if candidates:
            print_info_debug("[dns] resolve_ipv4_addresses_robust used primary resolver")
            return candidates

        hosts_candidates = self._resolve_ipv4_via_getent(fqdn)
        if hosts_candidates:
            print_info_debug("[dns] resolve_ipv4_addresses_robust used /etc/hosts")
            return hosts_candidates

        if self._should_try_systemd_stub_resolver():
            stub_candidates = self.resolve_ipv4_addresses(
                fqdn, resolver="127.0.0.53", tcp=tcp
            )
            if stub_candidates:
                print_info_debug(
                    "[dns] resolve_ipv4_addresses_robust used systemd-resolved stub"
                )
                return stub_candidates

        attempted_resolvers: list[str] = []
        for ns in self._get_resolv_conf_nameservers(include_loopback=False):
            if not ns:
                continue
            if resolver and ns == resolver:
                continue
            attempted_resolvers.append(ns)
            candidates = self.resolve_ipv4_addresses(fqdn, resolver=ns, tcp=tcp)
            if candidates:
                print_info_debug(
                    f"[dns] resolve_ipv4_addresses_robust used resolver {mark_sensitive(ns, 'ip')}"
                )
                return candidates

        if attempted_resolvers:
            marked = [mark_sensitive(ns, "ip") for ns in attempted_resolvers]
            print_info_debug(
                f"[dns] resolve_ipv4_addresses_robust exhausted resolver fallbacks: {marked}"
            )
        return []

    def reverse_resolve_fqdn(
        self,
        ip: str,
        resolver: str | None = None,
        *,
        tcp: bool = False,
    ) -> str | None:
        """Reverse-resolve an IP address to a hostname (PTR).

        This is a best-effort helper used to normalize NetExec/IP-based findings
        back into BloodHound computer objects (which are typically modeled by
        hostname/FQDN, not raw IPs).

        Args:
            ip: IPv4 address to reverse-resolve.
            resolver: Optional resolver IP to use (e.g. ADscan's local Unbound).
            tcp: Use TCP for DNS lookups when needed.

        Returns:
            Resolved hostname/FQDN without a trailing dot, or None if the PTR
            lookup fails.
        """
        ip_clean = (ip or "").strip()
        if not ip_clean:
            return None

        marked_ip = mark_sensitive(ip_clean, "ip")
        print_info_debug(
            f"[dns_reverse] Resolving PTR for IP: {marked_ip}, resolver: {resolver}"
        )

        try:
            reverse_name = dns.reversename.from_address(ip_clean).to_text().rstrip(".")
            query_result = self._query_dns_records(
                qname=reverse_name,
                rdtype="PTR",
                resolver=resolver,
                tcp=tcp,
                timeout_seconds=30,
                tries=1,
            )
            for candidate in query_result.answers:
                lower_candidate = candidate.lower()
                if not re.match(r"^[a-z0-9.-]+$", lower_candidate):
                    print_info_debug(
                        f"[dns_reverse] PTR ignored invalid hostname for {marked_ip}: {candidate}"
                    )
                    continue
                try:
                    ipaddress.ip_address(candidate.rstrip("."))
                except ValueError:
                    pass
                else:
                    print_info_debug(
                        f"[dns_reverse] PTR ignored IP-literal hostname for {marked_ip}: {candidate}"
                    )
                    continue
                marked_candidate = mark_sensitive(candidate, "host")
                print_info_debug(
                    f"[dns_reverse] PTR resolved {marked_ip} -> {marked_candidate}"
                )
                return candidate
            print_info_verbose(
                f"[dns_reverse] PTR lookup failed for {marked_ip}; no hostname could be resolved."
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_verbose(
                f"[dns_reverse] PTR lookup failed for {marked_ip} due to an exception."
            )
            print_exception(show_locals=False, exception=exc)

        return None

    def reverse_resolve_fqdn_robust(
        self,
        ip: str,
        resolver: str | None = None,
        preferred_resolvers: list[str] | None = None,
        *,
        tcp: bool = False,
    ) -> str | None:
        """Reverse-resolve an IP address with layered fallbacks."""
        resolved = self.reverse_resolve_fqdn(ip, resolver=resolver, tcp=tcp)
        if resolved:
            print_info_debug("[dns] reverse_resolve_fqdn_robust used primary resolver")
            return resolved

        reverse_getent = getattr(self, "_reverse_resolve_via_getent", None)
        if callable(reverse_getent):
            hosts_candidate = reverse_getent(ip)
            if hosts_candidate:
                print_info_debug("[dns] reverse_resolve_fqdn_robust used /etc/hosts")
                return hosts_candidate
        else:
            print_info_debug(
                "[dns] reverse_resolve_fqdn_robust: getent fallback unavailable in this runtime"
            )

        preferred_list = [r for r in (preferred_resolvers or []) if r]
        if resolver and resolver in preferred_list:
            preferred_list = [r for r in preferred_list if r != resolver]

        if preferred_list:
            for candidate_resolver in preferred_list:
                resolved = self.reverse_resolve_fqdn(
                    ip, resolver=candidate_resolver, tcp=tcp
                )
                if resolved:
                    print_info_debug(
                        f"[dns] reverse_resolve_fqdn_robust used preferred resolver "
                        f"{mark_sensitive(candidate_resolver, 'ip')}"
                    )
                    return resolved

        should_try_stub = getattr(self, "_should_try_systemd_stub_resolver", None)
        if callable(should_try_stub):
            if should_try_stub():
                stub_candidate = self.reverse_resolve_fqdn(
                    ip, resolver="127.0.0.53", tcp=tcp
                )
                if stub_candidate:
                    print_info_debug(
                        "[dns] reverse_resolve_fqdn_robust used systemd-resolved stub"
                    )
                    return stub_candidate
        else:
            print_info_debug(
                "[dns] reverse_resolve_fqdn_robust: systemd-resolved stub check unavailable in this runtime"
            )

        allow_public = True
        try:
            parsed_ip = ipaddress.ip_address(ip)
            allow_public = not parsed_ip.is_private
        except ValueError:
            allow_public = True
        if not allow_public:
            print_info_debug(
                "[dns] reverse_resolve_fqdn_robust: skipping public resolvers for private IP"
            )

        attempted_resolvers: list[str] = []
        for ns in self._get_resolv_conf_nameservers(include_loopback=False):
            if not ns:
                continue
            if resolver and ns == resolver:
                continue
            if preferred_list and ns in preferred_list:
                continue
            if not allow_public and not _is_private_or_loopback_ip(ns):
                continue
            attempted_resolvers.append(ns)
            resolved = self.reverse_resolve_fqdn(ip, resolver=ns, tcp=tcp)
            if resolved:
                print_info_debug(
                    f"[dns] reverse_resolve_fqdn_robust used resolver {mark_sensitive(ns, 'ip')}"
                )
                return resolved

        if attempted_resolvers:
            marked = [mark_sensitive(ns, "ip") for ns in attempted_resolvers]
            print_info_debug(
                f"[dns] reverse_resolve_fqdn_robust exhausted resolver fallbacks: {marked}"
            )
        return None


    def _get_resolv_conf_nameservers(self, *, include_loopback: bool) -> list[str]:
        nameservers: list[str] = []
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as rf:
                for raw in rf:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            ns = parts[1].strip()
                            if not ns:
                                continue
                            if not include_loopback and _is_loopback_ip(ns):
                                continue
                            if ns not in nameservers:
                                nameservers.append(ns)
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_info_debug(f"[dns] Failed to read /etc/resolv.conf: {exc}")
        return nameservers

    def _should_try_systemd_stub_resolver(self) -> bool:
        return "127.0.0.53" in self._get_resolv_conf_nameservers(
            include_loopback=True
        )

    def _resolve_ipv4_via_getent(self, fqdn: str) -> list[str]:
        fqdn_clean = (fqdn or "").strip()
        if not fqdn_clean:
            return []
        marked_fqdn = mark_sensitive(fqdn_clean, "domain")
        cmd = f"getent hosts {fqdn_clean}"
        result = self._host.run_command(cmd, timeout=15, ignore_errors=True)
        if not result or not result.stdout:
            return []
        candidates: list[str] = []
        for raw in result.stdout.splitlines():
            parts = raw.strip().split()
            if not parts:
                continue
            ip = parts[0].strip()
            if not ip or _is_loopback_ip(ip):
                continue
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                if ip not in candidates:
                    candidates.append(ip)
        if candidates:
            print_info_debug(
                f"[dns] getent resolved {marked_fqdn} -> {candidates}"
            )
        return candidates

    def _reverse_resolve_via_getent(self, ip: str) -> str | None:
        ip_clean = (ip or "").strip()
        if not ip_clean:
            return None
        marked_ip = mark_sensitive(ip_clean, "ip")
        cmd = f"getent hosts {ip_clean}"
        result = self._host.run_command(cmd, timeout=15, ignore_errors=True)
        if not result or not result.stdout:
            return None
        candidates: list[str] = []
        for raw in result.stdout.splitlines():
            parts = raw.strip().split()
            if len(parts) < 2:
                continue
            if parts[0].strip() != ip_clean:
                continue
            for candidate in parts[1:]:
                cleaned = candidate.strip().rstrip(".")
                if not cleaned:
                    continue
                if not re.match(r"^[a-z0-9.-]+$", cleaned.lower()):
                    continue
                if "." not in cleaned:
                    continue
                candidates.append(cleaned)

        if not candidates:
            return None

        selected = max(candidates, key=lambda value: (value.count("."), len(value)))
        print_info_debug(
            f"[dns_reverse] getent resolved {marked_ip} -> {mark_sensitive(selected, 'host')}"
        )
        return selected

    def find_pdc_via_resolver(self, *, domain: str, resolver_ip: str) -> str | None:
        """Resolve the PDC IP for a domain using a specific resolver.

        Uses direct SRV lookups and supports TCP fallback (useful when UDP/53 is blocked).
        Returns the first resolved IPv4 address for the SRV target.
        """
        normalized_domain = (domain or "").strip().rstrip(".")
        if not normalized_domain or not resolver_ip:
            return None

        marked_domain = mark_sensitive(normalized_domain, "domain")
        marked_ip = mark_sensitive(resolver_ip, "ip")

        srv_name = f"_ldap._tcp.pdc._msdcs.{normalized_domain}"
        marked_srv = f"_ldap._tcp.pdc._msdcs.{marked_domain}"

        print_info_debug(
            f"[dns_find_pdc_resolv] Executing PDC SRV query for {marked_srv} via {marked_ip}"
        )

        srv_targets, _ = self.dig_srv_records_robust(
            srv_name=srv_name,
            resolver=resolver_ip,
            tcp=False,
            allow_fallback=False,
        )
        if not srv_targets:
            print_warning_debug(
                f"[dns_find_pdc_resolv] No PDC SRV answer via UDP for {marked_domain} via resolver {marked_ip}. "
                "Attempting TCP fallback."
            )
            srv_targets, _ = self.dig_srv_records_robust(
                srv_name=srv_name,
                resolver=resolver_ip,
                tcp=True,
                allow_fallback=False,
            )
        if not srv_targets:
            return None

        # Resolve the first SRV target to an IP.
        target = srv_targets[0].strip()
        if not target:
            return None
        ips = self.resolve_ipv4_addresses_robust(
            target.rstrip("."), resolver=resolver_ip, tcp=False
        )
        return ips[0] if ips else None

    def discover_pdc_srv_target(self, *, domain: str, resolver_ip: str) -> str | None:
        """Return the first PDC SRV target hostname for a domain via a resolver.

        This is a utility for higher-level callers that need the hostname label (PDC hostname)
        for /etc/hosts updates and later FQDN construction.
        """
        normalized_domain = (domain or "").strip().rstrip(".")
        if not normalized_domain or not resolver_ip:
            return None

        srv_name = f"_ldap._tcp.pdc._msdcs.{normalized_domain}"
        targets, _ = self.dig_srv_records_robust(
            srv_name=srv_name, resolver=resolver_ip, tcp=False
        )
        if not targets:
            targets, _ = self.dig_srv_records_robust(
                srv_name=srv_name, resolver=resolver_ip, tcp=True
            )

        if not targets:
            return None
        return targets[0].strip().rstrip(".") or None

    def find_pdc_with_selection(
        self,
        *,
        domain: str,
        resolver_ip: str,
        preferred_ips: list[str | None] | None = None,
        reference_ip: str | None = None,
    ) -> tuple[str | None, str | None]:
        """Resolve PDC IP and hostname using a specific resolver with IP selection.

        This extends find_pdc_via_resolver to include preferred IP selection logic
        and returns both the selected IP and the hostname.

        Args:
            domain: Domain name to query
            resolver_ip: DNS resolver IP to use
            preferred_ips: List of preferred IPs in priority order
            reference_ip: Reference IP for subnet matching

        Returns:
            Tuple of (selected_ip, hostname) or (None, None) if not found
        """
        normalized_domain = (domain or "").strip().rstrip(".")
        if not normalized_domain or not resolver_ip:
            return None, None

        marked_domain = mark_sensitive(normalized_domain, "domain")
        marked_ip = mark_sensitive(resolver_ip, "ip")

        srv_name = f"_ldap._tcp.pdc._msdcs.{normalized_domain}"
        marked_srv = f"_ldap._tcp.pdc._msdcs.{marked_domain}"

        srv_targets: list[str] = []
        print_info_debug(
            f"[dns_find_pdc_resolv] Executing PDC SRV query for {marked_srv} via {marked_ip}"
        )

        srv_targets, _ = self.dig_srv_records_robust(
            srv_name=srv_name,
            resolver=resolver_ip,
            tcp=False,
            allow_fallback=False,
        )
        if not srv_targets:
            print_warning_debug(
                f"[dns_find_pdc_resolv] No PDC SRV answer via UDP for {marked_domain} via resolver {marked_ip}. "
                "Attempting TCP fallback."
            )
            srv_targets, _ = self.dig_srv_records_robust(
                srv_name=srv_name,
                resolver=resolver_ip,
                tcp=True,
                allow_fallback=False,
            )

        if not srv_targets:
            print_warning_debug(
                f"[dns_find_pdc_resolv] No PDC SRV answer for {marked_domain} via resolver {marked_ip}"
            )
            return None, None

        hostname = srv_targets[0].rstrip(".")
        if not hostname:
            return None, None

        pdc_hostname = hostname.split(".")[0]
        fqdn = f"{pdc_hostname}.{normalized_domain}"
        ip_candidates = self.resolve_ipv4_addresses_robust(
            fqdn, resolver=resolver_ip, tcp=False
        )

        selected_ip = choose_preferred_pdc_ip(
            ip_candidates,
            preferred_ips=preferred_ips,
            reference_ip=reference_ip,
        )

        if selected_ip:
            marked_ip_candidates = mark_sensitive(ip_candidates, "ip")
            print_info_debug(
                f"[DNS] Selected PDC IP via resolver {marked_ip} for {marked_domain}: {selected_ip} (candidates={marked_ip_candidates})"
            )
            return selected_ip, pdc_hostname

        marked_ip_candidates = mark_sensitive(ip_candidates, "ip")
        print_warning_debug(
            f"[DNS] Resolver {marked_ip} returned candidates {marked_ip_candidates} but none selected for {marked_domain}"
        )
        return None, None

    def discover_domain_controllers(
        self,
        *,
        domain: str,
        pdc_ip: str | None = None,
        preferred_ips: list[str | None] | None = None,
    ) -> tuple[list[str], list[str], dict[str, str]]:
        """Discover all domain controllers for a domain via SRV records.

        Args:
            domain: Domain name to query
            pdc_ip: Optional known PDC IP for IP selection preference
            preferred_ips: Optional list of preferred IPs for selection

        Returns:
            Tuple of (dc_ips, dc_hostnames, dc_ip_to_hostname):
            - dc_ips: List of unique DC IP addresses
            - dc_hostnames: List of DC hostnames (FQDNs)
            - dc_ip_to_hostname: Mapping of IP -> hostname for each DC
        """
        normalized_domain = (domain or "").strip().rstrip(".")
        if not normalized_domain:
            return [], [], {}

        marked_domain = mark_sensitive(normalized_domain, "domain")
        marked_pdc_ip = mark_sensitive(pdc_ip, "ip") if pdc_ip else None
        print_info_debug(
            f"[dns_find_dcs] Starting DC discovery for domain: {marked_domain}, pdc_ip: {marked_pdc_ip}"
        )

        srv_name = f"_ldap._tcp.dc._msdcs.{normalized_domain}"
        if pdc_ip:
            print_info_debug(
                f"[dns_find_dcs] Executing SRV query for _ldap._tcp.dc._msdcs.{marked_domain} via {mark_sensitive(pdc_ip, 'ip')}"
            )
        else:
            print_info_debug(
                f"[dns_find_dcs] Executing SRV query for _ldap._tcp.dc._msdcs.{marked_domain}"
            )

        dc_hostnames, srv_error = self.dig_srv_records_robust(
            srv_name=srv_name, resolver=pdc_ip, tcp=False
        )
        if srv_error:
            print_info_debug(
                f"[dns_find_dcs] SRV query returned no results for {marked_domain}: error={srv_error}"
            )
        print_info_debug(
            f"[dns_find_dcs] Found {len(dc_hostnames)} DC hostname(s): {dc_hostnames}"
        )

        dc_ip_to_hostname: dict[str, str] = {}

        # For each hostname, resolve its IP
        for dc in dc_hostnames:
            print_info_debug(f"[dns_find_dcs] Resolving IP for DC hostname: {dc}")
            ip_candidates = self.resolve_ipv4_addresses_robust(dc, resolver=pdc_ip)
            print_info_debug(f"[dns_find_dcs] IP candidates for {dc}: {ip_candidates}")

            # Build preferred IPs list
            pref_list = preferred_ips or []
            if pdc_ip and pdc_ip not in pref_list:
                pref_list = [pdc_ip] + pref_list

            reference_ip = pdc_ip
            selected_ip = choose_preferred_pdc_ip(
                ip_candidates,
                preferred_ips=pref_list if pref_list else None,
                reference_ip=reference_ip,
            )

            marked_reference_ip = (
                mark_sensitive(reference_ip, "ip") if reference_ip else None
            )
            marked_selected_ip = (
                mark_sensitive(selected_ip, "ip") if selected_ip else None
            )
            marked_candidates = mark_sensitive(ip_candidates, "ip")
            print_info_debug(
                f"[dns_find_dcs] IP selection for DC hostname {dc}: "
                f"reference_ip={marked_reference_ip}, candidates={marked_candidates}, selected={marked_selected_ip}"
            )

            if selected_ip:
                print_info_debug(f"[dns_find_dcs] Selected IP for {dc}: {selected_ip}")
                dc_ip_to_hostname.setdefault(selected_ip, dc)
            else:
                print_warning_debug(
                    f"[dns_find_dcs] Could not select IP for {dc} from candidates {ip_candidates}"
                )

        dc_ips = list(dc_ip_to_hostname.keys())
        print_info_debug(f"[dns_find_dcs] Final DC IPs list: {dc_ips}")

        return dc_ips, dc_hostnames, dc_ip_to_hostname

    def discover_pdc(
        self,
        *,
        domain: str,
        preferred_ips: list[str | None] | None = None,
    ) -> tuple[str | None, str | None]:
        """Discover PDC for a domain using SRV queries.

        Args:
            domain: Domain name to query
            preferred_ips: Optional list of preferred IPs for selection

        Returns:
            Tuple of (selected_ip, hostname) or (None, None) if not found
        """
        normalized_domain = (domain or "").strip().rstrip(".")
        if not normalized_domain:
            return None, None

        marked_domain = mark_sensitive(normalized_domain, "domain")
        print_info_debug(
            f"[dns_find_pdc] Starting PDC discovery for domain: {marked_domain}"
        )

        srv_name = f"_ldap._tcp.pdc._msdcs.{normalized_domain}"
        marked_srv = f"_ldap._tcp.pdc._msdcs.{marked_domain}"
        print_info_debug(
            f"[dns_find_pdc] Executing PDC SRV query: {marked_srv}"
        )

        targets, _srv_error = self.dig_srv_records_robust(srv_name=srv_name)
        if not targets:
            print_warning_debug(
                f"[dns_find_pdc] No PDC hostname found in SRV query result for domain {marked_domain}"
            )
            return None, None

        pdc_hostname = targets[0].split(".")[0]
        fqdn = f"{pdc_hostname}.{normalized_domain}"
        marked_fqdn = mark_sensitive(fqdn, "domain")
        marked_pdc_hostname_1 = mark_sensitive(pdc_hostname, "hostname")
        print_info_debug(
            f"[dns_find_pdc] Found PDC hostname: {marked_pdc_hostname_1}, FQDN: {marked_fqdn}"
        )

        ip_candidates = self.resolve_ipv4_addresses_robust(fqdn)
        print_info_debug(
            f"[dns_find_pdc] IP candidates for PDC FQDN {marked_fqdn}: {ip_candidates}"
        )

        selected_ip = choose_preferred_pdc_ip(
            ip_candidates, preferred_ips=preferred_ips
        )

        if selected_ip:
            marked_domain = mark_sensitive(normalized_domain, "domain")
            print_info_debug(
                f"[DNS] Selected PDC IP for {marked_domain}: {selected_ip} (candidates={ip_candidates})"
            )
            return selected_ip, pdc_hostname

        marked_domain = mark_sensitive(normalized_domain, "domain")
        print_warning_debug(
            f"[DNS] Could not determine PDC IP from candidates {ip_candidates} for {marked_domain}"
        )
        return None, None

    def verify_dns_resolution(
        self,
        *,
        domain: str,
        resolver_ip: str,
    ) -> tuple[bool, str | None]:
        """Verify DNS resolution for a domain via SRV records and apex A record.

        Args:
            domain: Domain name to verify
            resolver_ip: DNS resolver IP to use for verification

        Returns:
            Tuple of (is_resolvable, error_kind):
            - is_resolvable: True if DNS resolution is working
            - error_kind: Error kind if not resolvable ("timeout", "no_answer", "servfail", etc.)
        """
        normalized_domain = (domain or "").strip().rstrip(".")
        if not normalized_domain:
            return False, "invalid_domain"

        marked_domain = mark_sensitive(normalized_domain, "domain")

        srv_names = [
            f"_ldap._tcp.dc._msdcs.{normalized_domain}",
            f"_ldap._tcp.pdc._msdcs.{normalized_domain}",
        ]

        # Try SRV records first
        for srv_name in srv_names:
            srv_result = self._query_dns_records(
                qname=srv_name,
                rdtype="SRV",
                resolver=resolver_ip,
                tcp=False,
                timeout_seconds=15,
                tries=1,
            )
            if srv_result.answers:
                return True, None
            if srv_result.error == "timeout":
                print_warning(
                    f"Local DNS resolver did not respond in time while verifying {marked_domain}."
                )
                return False, "timeout"

        # As a last resort, try resolving the domain itself (may still be NXDOMAIN in AD labs)
        apex_result = self._query_dns_records(
            qname=normalized_domain,
            rdtype="A",
            resolver=resolver_ip,
            tcp=False,
            timeout_seconds=10,
            tries=1,
        )
        if apex_result.error == "timeout":
            print_warning(
                f"Local DNS resolver did not respond in time while verifying {marked_domain}."
            )
            return False, "timeout"

        if apex_result.answers:
            return True, None

        # Check for SERVFAIL and detect whether checking-disabled queries would succeed.
        for srv_name in srv_names:
            verbose_result = self._query_dns_records(
                qname=srv_name,
                rdtype="SRV",
                resolver=resolver_ip,
                tcp=False,
                timeout_seconds=15,
                tries=1,
            )
            if verbose_result.error != "servfail":
                continue
            print_info_debug(
                f"[dns] SRV status for {marked_domain}: SERVFAIL"
            )
            cd_result = self._query_dns_records(
                qname=srv_name,
                rdtype="SRV",
                resolver=resolver_ip,
                tcp=False,
                timeout_seconds=15,
                tries=1,
                checking_disabled=True,
            )
            if cd_result.answers:
                return False, "servfail"

        return False, "no_answer"

    def resolve_ipv4_addresses_with_resolver(
        self, fqdn: str, *, resolver: str, tcp: bool = False
    ) -> list[str]:
        """Resolve IPv4 addresses using a fixed resolver only (no fallbacks)."""
        normalized = (fqdn or "").strip()
        if not normalized or not resolver:
            return []
        marked_fqdn = mark_sensitive(normalized, "host")
        marked_resolver = mark_sensitive(resolver, "ip")
        print_info_debug(
            f"[dns] resolve_ipv4_addresses_with_resolver: {marked_fqdn} via {marked_resolver}"
        )
        return self.resolve_ipv4_addresses(normalized, resolver=resolver, tcp=tcp)

    def select_working_resolver_for_domain(
        self,
        domain: str,
        *,
        preferred_resolvers: list[str] | None = None,
    ) -> str | None:
        """Pick a resolver that can answer SRV queries for the domain.

        This is used to avoid per-host fallback storms in large domains by
        selecting a working resolver once and reusing it for bulk lookups.
        """
        normalized_domain = (domain or "").strip().rstrip(".")
        if not normalized_domain:
            return None

        srv_name = f"_ldap._tcp.dc._msdcs.{normalized_domain}"
        candidates: list[str] = []
        for resolver in preferred_resolvers or []:
            if resolver and resolver not in candidates:
                candidates.append(resolver)

        get_resolv_nameservers = getattr(self, "_get_resolv_conf_nameservers", None)
        if callable(get_resolv_nameservers):
            for ns in get_resolv_nameservers(include_loopback=True):
                if ns and ns not in candidates:
                    candidates.append(ns)

        if not candidates:
            return None

        marked_domain = mark_sensitive(normalized_domain, "domain")
        for resolver in candidates:
            marked_resolver = mark_sensitive(resolver, "ip")
            print_info_debug(
                f"[dns] Testing resolver {marked_resolver} for {marked_domain}"
            )
            targets, error = self.dig_srv_records_robust(
                srv_name=srv_name,
                resolver=resolver,
                tcp=False,
                allow_fallback=False,
            )
            if targets:
                print_info_debug(
                    f"[dns] Selected resolver {marked_resolver} for {marked_domain}"
                )
                return resolver
            print_info_debug(
                f"[dns] Resolver {marked_resolver} did not answer SRV "
                f"(error={error})"
            )

        return None

    def check_dns_resolution(
        self,
        *,
        domain: str,
        resolver_ip: str | None = None,
        auto_configure: bool = True,
        allow_fallback: bool = True,
    ) -> tuple[bool, str | None]:
        """Check DNS resolution for a domain and optionally auto-configure if needed.

        This method verifies that DNS resolution is working for a domain by:
        1. Checking if the system resolver is using the local Unbound instance
        2. Querying SRV records for domain controllers
        3. Testing IP resolution for DC hostnames
        4. Optionally attempting auto-configuration if resolution fails

        Args:
            domain: Domain name to check
            resolver_ip: Optional resolver IP to use (if None, uses system resolver)
            auto_configure: If True, attempts to auto-configure DNS when resolution fails

        Returns:
            Tuple of (is_working, error_kind):
            - is_working: True if DNS resolution is working correctly
            - error_kind: Error kind if not working ("timeout", "no_answer", "servfail", etc.)
        """
        from adscan_internal.rich_output import (
            print_info_debug,
            print_success_verbose,
            print_warning_debug,
        )

        normalized_domain = (domain or "").strip().rstrip(".")
        if not normalized_domain:
            return False, "invalid_domain"

        marked_domain = mark_sensitive(normalized_domain, "domain")
        marked_resolver_ip = mark_sensitive(resolver_ip, "ip") if resolver_ip else None

        print_info_debug(
            f"[check_dns_resolution] Starting DNS check for domain: {marked_domain}, "
            f"resolver_ip: {marked_resolver_ip}"
        )

        srv_name = f"_ldap._tcp.dc._msdcs.{normalized_domain}"

        # Query SRV records using system resolver (validates what the rest of the tooling will use)
        print_info_debug(
            f"[check_dns_resolution] Executing SRV query for _ldap._tcp.dc._msdcs.{marked_domain}"
        )

        srv_targets, srv_error = self.dig_srv_records_robust(
            srv_name=srv_name,
            resolver=resolver_ip,
            tcp=False,
            allow_fallback=allow_fallback,
        )

        no_servers = srv_error == "no_servers"
        error_found = srv_error in {"timeout", "command_failed", "invalid_srv_name"}

        print_info_debug(
                f"[check_dns_resolution] SRV targets={len(srv_targets)}, srv_error={srv_error}"
            )

        if not srv_targets:
            # A successful DNS invocation can still return an empty answer set.
            # For AD domains, missing SRV records typically means conditional forwarding isn't active.
            print_warning_debug(
                f"[check_dns_resolution] SRV query returned no targets for {marked_domain} "
                f"(srv_error={srv_error})."
            )

            if error_found or no_servers:
                if auto_configure and resolver_ip:
                    print_info_debug(
                        "[check_dns_resolution] Auto-configuration requested but resolver_ip provided, "
                        "skipping auto-config"
                    )
                    return False, srv_error or "no_targets"
                return False, srv_error or "no_targets"

            # If no error but no targets, DNS may be partially working
            return False, "no_targets"

        # DNS SRV query succeeded, verify we can actually resolve DC hostnames to IPs
        print_info_debug(
            "[check_dns_resolution] SRV query succeeded, extracting DC hostnames from output"
        )
        dc_hostnames = srv_targets
        print_info_debug(
            f"[check_dns_resolution] Found {len(dc_hostnames)} DC hostname(s) in SRV response: "
            f"{dc_hostnames}"
        )

        if dc_hostnames:
            # Test if we can actually resolve at least one DC hostname to an IP
            test_fqdn = dc_hostnames[0].rstrip(".")  # Remove trailing dot if present
            print_info_debug(
                f"[check_dns_resolution] Testing IP resolution for first DC: {test_fqdn}"
            )
            test_ips = self.resolve_ipv4_addresses_robust(
                test_fqdn, resolver=resolver_ip
            )
            print_info_debug(
                f"[check_dns_resolution] IP resolution test for {test_fqdn} returned: {test_ips}"
            )

            if not test_ips:
                print_warning_debug(
                    f"[check_dns_resolution] DNS SRV query succeeded but cannot resolve DC hostname "
                    f"{test_fqdn} to IP"
                )
                print_warning_debug(
                    "[check_dns_resolution] This indicates DNS is partially working (SRV records) "
                    "but A record resolution may be failing"
                )
                # Still return True because SRV query worked, but log the issue
            else:
                print_info_debug(
                    f"[check_dns_resolution] Successfully resolved {test_fqdn} to IP(s): {test_ips}"
                )
        else:
            print_warning_debug(
                "[check_dns_resolution] SRV query succeeded but no DC hostnames found in response"
            )

        print_success_verbose("DNS resolution is working correctly.")
        return True, None
