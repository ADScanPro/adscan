"""Bulk DNS resolution for Computer nodes using dnspython (async).

Uses the DC IP as the sole resolver — in a lab or customer engagement the DC
always knows its own A records, so we avoid dependency on external DNS.

This resolves every Computer hostname concurrently through ``dns.asyncresolver``
(dnspython is a first-class dependency, no external binary). It replaced the
former ``massdns`` C-binary subprocess on 2026-09-03: a 5000-host A/B benchmark
(4000 resolvable / 500 NXDOMAIN / 500 silent-drop, single resolver) measured
dnspython async at ~7.7s vs massdns at ~25.1s with identical coverage. massdns
loses at scale because it pays its per-dead-host retry budget (50 x 500ms)
roughly serially, while dnspython at high in-flight concurrency overlaps every
dead-host timeout. See
``docs/superpowers/specs/2026-09-03-windows-native-runtime-portability-design.md``
(§4, "RESOLVED (2026-09-03 benchmark)").

This is Phase 2 of the two-phase resolution flow: it runs during attack-graph
collection, annotates each resolved Computer node with its first IPv4 in
memory, and — when an ``output_dir`` is supplied — persists a
``massdns_resolution_report.json`` using the shared report service in
``adscan_internal/services/reachability/massdns_report.py`` (the same schema
Phase 3, ``cli/nmap``, writes and the Kerberos hostname inventory consumes). The
report filename and schema are kept unchanged for backward compatibility with
that consumer even though massdns is gone — the payload shape is a consumed
contract, not a description of the tool that produced it.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import time
from typing import TYPE_CHECKING

import dns.asyncresolver
import dns.exception
import dns.resolver

from adscan_core import telemetry

from adscan_internal import print_info_debug, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.collector.models import is_collectable_computer_host
from adscan_internal.services.reachability.massdns_report import (
    _write_massdns_resolution_report,
)
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:
    from adscan_internal.services.collector.models import CollectionResult

# Phase 2 writes its side artifacts under distinct filenames so it never
# clobbers the Phase-3-owned files (``enabled_computers_ips.txt``,
# ``massdns_output.jsonl``, ``massdns_hosts.txt``) in the same domain dir. The
# shared report file (``massdns_resolution_report.json``) is intentionally the
# same path both phases use — its schema is identical (C2 builder) and the
# Kerberos hostname inventory reads it from there. The name is retained for
# backward compat with that consumer; the payload is not massdns-specific.
_REPORT_FILENAME = "massdns_resolution_report.json"
_COLLECTOR_RESOLVED_IP_FILENAME = "collector_resolved_ips.txt"
_COLLECTOR_RAW_OUTPUT_FILENAME = "collector_massdns_output.jsonl"

# HARD REQUIREMENT — high in-flight concurrency is not a tuning knob, it is the
# reason dnspython beats massdns. At scale the dominating cost is DEAD hosts:
# each NXDOMAIN/timeout burns the full per-query lifetime, and only overlapping
# hundreds of those at once amortizes it. The 5000-host benchmark showed
# dnspython at c=1000 is ~3.2x faster than massdns, but at c=100 it LOSES
# because the dead-host timeouts serialize. Do NOT lower this to a "safe"
# default. It is only bounded to protect the local socket/FD budget, not to
# throttle the DC (a single resolver answering cached A records is cheap; the
# DC does the same lookups massdns issued). Overridable via
# ``ADSCAN_DNS_RESOLVE_CONCURRENCY`` for a constrained host.
_DNS_RESOLVE_CONCURRENCY = 1000

# Per-query budget. dnspython uses ``timeout`` as the per-ATTEMPT wait and
# ``lifetime`` as the TOTAL budget for one name, retrying attempts until the
# lifetime is spent (``_compute_timeout`` = ``min(lifetime - elapsed, timeout)``,
# looped). So the effective retry count is roughly ``lifetime / timeout``.
#
# ``lifetime`` MUST be several times ``timeout`` — with ``lifetime == timeout``
# there is budget for exactly ONE attempt, so a single dropped UDP datagram
# leaves that host unresolved forever. This was MEASURED: at 5000 hosts,
# ``lifetime == timeout`` silently lost ~140-160 hosts to un-retried UDP drops;
# only ``lifetime >= ~3x timeout`` (room for ~3 attempts) gave perfect
# 4000/4000 coverage. Silently dropping ~150 targets in an AD pentest is a
# truncated-result violation of the Exposure-Validation doctrine — unacceptable.
# 2.0s per attempt x 6.0s total => ~3 attempts, and 500 dead hosts fully
# overlapped still cost ~6s total (not N x 6s) thanks to the concurrency below.
_DNS_QUERY_TIMEOUT_SECS = 2.0
_DNS_QUERY_LIFETIME_SECS = 6.0


def _resolve_concurrency() -> int:
    """Return the in-flight resolution limit (env override, floored high).

    The floor exists because a conservative concurrency defeats the whole
    migration (see ``_DNS_RESOLVE_CONCURRENCY``). An operator on a constrained
    host may lower it via ``ADSCAN_DNS_RESOLVE_CONCURRENCY``, but a bogus/tiny
    value is clamped up to a sane minimum.
    """
    raw = os.getenv("ADSCAN_DNS_RESOLVE_CONCURRENCY")
    if not raw:
        return _DNS_RESOLVE_CONCURRENCY
    try:
        value = int(raw)
    except ValueError:
        return _DNS_RESOLVE_CONCURRENCY
    return max(value, 1)


def _is_ipv4(ip: str) -> bool:
    """Return True if ``ip`` is a syntactically-valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def _first_ipv4(ips: list[str]) -> str | None:
    """Return the first syntactically-valid IPv4 in ``ips`` (order preserved)."""
    for ip in ips:
        if _is_ipv4(ip):
            return ip
    return None


def _build_async_resolver(resolver_ips: list[str]) -> "dns.asyncresolver.Resolver":
    """Build an async resolver pinned to the supplied nameserver(s).

    Args:
        resolver_ips: One or more resolver IPs (the DC, plus any configured DNS
            servers). dnspython tries them in order per query, so passing the
            DC first preserves the "the DC knows its own A records" behaviour.
    """
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = list(resolver_ips)
    resolver.timeout = _DNS_QUERY_TIMEOUT_SECS
    resolver.lifetime = _DNS_QUERY_LIFETIME_SECS
    return resolver


async def _resolve_one(
    resolver: "dns.asyncresolver.Resolver",
    hostname: str,
    sem: asyncio.Semaphore,
) -> tuple[str, list[str]]:
    """Resolve one hostname to its A records under the concurrency semaphore.

    A dead host (NXDOMAIN / NoAnswer / timeout / any resolver error) yields an
    empty IP list — never raises, so it can never stall or abort the batch.
    """
    async with sem:
        try:
            answer = await resolver.resolve(hostname, "A")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            return hostname, []
        except Exception as exc:  # noqa: BLE001 — defensive: one host must not kill the batch
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return hostname, []

    ips: list[str] = []
    for rdata in answer:
        ip = str(getattr(rdata, "address", "") or "").strip()
        if ip and ip not in ips:
            ips.append(ip)
    return hostname, ips


async def _resolve_all(
    hostnames: list[str], resolver_ips: list[str]
) -> dict[str, list[str]]:
    """Resolve every hostname concurrently → hostname → ordered IPv4 list.

    Only IPv4 answers are kept (parity with the old ``-t A`` path). Hosts with
    no IPv4 answer are omitted from the returned map.
    """
    resolver = _build_async_resolver(resolver_ips)
    sem = asyncio.Semaphore(_resolve_concurrency())
    tasks = [
        asyncio.create_task(_resolve_one(resolver, hostname, sem))
        for hostname in hostnames
    ]
    host_to_ips: dict[str, list[str]] = {}
    for hostname, ips in await asyncio.gather(*tasks):
        ipv4s = [ip for ip in ips if _is_ipv4(ip)]
        if ipv4s:
            host_to_ips[hostname] = ipv4s
    return host_to_ips


def resolve_hostnames_to_ipv4(
    hostnames: list[str],
    resolver_ips: list[str],
) -> dict[str, list[str]]:
    """Bulk-resolve hostnames to IPv4 via dnspython async (no external binary).

    This is the SSOT for name→IP resolution outside the collector's Computer-node
    flow. It reuses the same concurrency-bounded async resolver machinery
    (``_resolve_all``/``_resolve_one``), so callers inherit the high-in-flight
    dead-host amortization, the per-query retry budget, and the "one bad host
    never aborts the batch" guarantee. Works on any platform (Windows included) —
    it replaced the ``massdns`` C-binary subprocess in the Phase-3 nmap
    resolution path.

    Args:
        hostnames: Hostnames to resolve (case/dot-insensitive; normalized in the
            returned keys). Duplicates are resolved once.
        resolver_ips: Resolver IPs to query in order (typically the domain's DC
            plus any configured DNS servers) — the same set the old massdns
            resolvers file was built from.

    Returns:
        A mapping of normalized hostname (lowercased, trailing dot stripped) to
        its ordered list of resolved IPv4 addresses. Hosts with no IPv4 answer
        are omitted. Empty inputs yield an empty map (no network activity).
    """
    normalized_hosts = [
        h for h in (str(host or "").strip().rstrip(".").lower() for host in hostnames) if h
    ]
    unique_hosts = list(dict.fromkeys(normalized_hosts))
    clean_resolvers = [str(ip or "").strip() for ip in resolver_ips]
    clean_resolvers = [ip for ip in clean_resolvers if ip]
    if not unique_hosts or not clean_resolvers:
        return {}

    print_info_verbose(
        f"[dns-resolver] resolving {len(unique_hosts)} hostnames "
        f"(async, up to {_resolve_concurrency()} in-flight)"
    )
    started = time.monotonic()
    try:
        host_to_ips = asyncio.run(_resolve_all(unique_hosts, clean_resolvers))
    except Exception as exc:  # noqa: BLE001 — resolution is best-effort; a failure must not abort the caller
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug("[dns-resolver] async resolution failed — returning no IPs")
        return {}
    elapsed = time.monotonic() - started
    print_info_debug(
        f"[dns-resolver] resolved {len(host_to_ips)}/{len(unique_hosts)} hostnames "
        f"in {elapsed:.1f}s"
    )
    return {
        host: [ip for ip in ips if _is_ipv4(ip)]
        for host, ips in host_to_ips.items()
        if [ip for ip in ips if _is_ipv4(ip)]
    }


def resolve_computer_nodes(
    result: "CollectionResult",
    dc_ip: str,
    *,
    timeout: int = 60,
    output_dir: str | None = None,
    domain: str | None = None,
) -> int:
    """Resolve Computer node hostnames to IPs via dnspython async.

    Writes ``ip_address`` (the first resolved IPv4) into each resolved Computer
    node's properties. When ``output_dir`` is supplied, also persists a
    ``massdns_resolution_report.json`` (multi-IP, shared schema) plus the
    collector-owned resolved-IP and raw-output side artifacts into that
    directory.

    Args:
        result: The collection result whose Computer nodes are annotated.
        dc_ip: DC IP used as the sole DNS resolver.
        timeout: Retained for signature/back-compat with existing callers. The
            per-query budget is governed by ``_DNS_QUERY_LIFETIME_SECS``; this
            value is not used to cap the async batch (dead hosts fail fast on
            their own), so a large legacy value never stalls the batch.
        output_dir: Workspace domain dir to persist the report into; when None
            the function behaves exactly as before — in-memory annotation only,
            no file written.
        domain: Domain name stamped into the persisted report context.

    Returns:
        The number of nodes that received an IP.
    """
    del timeout  # kept for back-compat; per-query budget is fixed above.

    computers = [n for n in result.nodes.values() if is_collectable_computer_host(n)]
    hostnames = [
        str(n.properties.get("dnshostname") or "").strip().lower() for n in computers
    ]
    hostnames = [h for h in hostnames if h]
    if not hostnames:
        return 0

    # Deduplicate on the wire — many Computer nodes can share a dnshostname only
    # in pathological data, but we still resolve each unique name once.
    unique_hostnames = list(dict.fromkeys(hostnames))

    print_info_verbose(
        f"[dns-resolver] resolving {len(unique_hostnames)} hostnames "
        f"(async, up to {_resolve_concurrency()} in-flight)"
    )
    started = time.monotonic()
    try:
        host_to_ips = asyncio.run(_resolve_all(unique_hostnames, [dc_ip]))
    except Exception as exc:  # noqa: BLE001 — resolution is best-effort; a failure must not abort collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug("[dns-resolver] async resolution failed — skipping IP resolution")
        return 0
    elapsed = time.monotonic() - started

    resolved = 0
    for node in computers:
        dns_name = str(node.properties.get("dnshostname") or "").strip().lower()
        if not dns_name:
            continue
        ips = host_to_ips.get(dns_name)
        if ips:
            first = _first_ipv4(ips)
            if first:
                node.properties["ip_address"] = first
                resolved += 1

    print_info_debug(
        f"[dns-resolver] resolved {resolved}/{len(computers)} computers "
        f"in {elapsed:.1f}s"
    )

    if output_dir:
        # The report/side-artifact writer keys off the ORIGINAL per-node
        # hostname order (with dupes) so its unique-IP ordering matches what
        # every existing consumer expects.
        _persist_resolution_report(
            output_dir=output_dir,
            hostnames=hostnames,
            host_to_ips=host_to_ips,
            domain=domain,
            dc_ip=dc_ip,
        )

    return resolved


def _persist_resolution_report(
    *,
    output_dir: str,
    hostnames: list[str],
    host_to_ips: dict[str, list[str]],
    domain: str | None,
    dc_ip: str,
) -> None:
    """Persist the shared resolution report plus collector-owned side artifacts."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        resolved_ip_file = os.path.join(output_dir, _COLLECTOR_RESOLVED_IP_FILENAME)
        raw_output_file = os.path.join(output_dir, _COLLECTOR_RAW_OUTPUT_FILENAME)
        report_path = os.path.join(output_dir, _REPORT_FILENAME)

        # Flat resolved-IP file (unique, hostname/input order preserved).
        unique_ips: list[str] = []
        seen_ips: set[str] = set()
        raw_lines: list[str] = []
        seen_hosts: set[str] = set()
        for hostname in hostnames:
            if hostname in seen_hosts:
                continue
            seen_hosts.add(hostname)
            ips = host_to_ips.get(hostname, [])
            if ips:
                raw_lines.append(json.dumps({"name": hostname, "ips": ips}))
            for ip in ips:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    unique_ips.append(ip)

        with open(resolved_ip_file, "w", encoding="utf-8") as fh:
            for ip in unique_ips:
                fh.write(f"{ip}\n")
        with open(raw_output_file, "w", encoding="utf-8") as fh:
            for line in raw_lines:
                fh.write(f"{line}\n")

        written = _write_massdns_resolution_report(
            report_path,
            hostnames=list(dict.fromkeys(hostnames)),
            host_to_ips=host_to_ips,
            domain=domain,
            resolvers=[dc_ip],
            ip_file=resolved_ip_file,
            raw_output_file=raw_output_file,
        )
        if written:
            print_info_debug(
                f"[dns-resolver] persisted resolution report "
                f"{mark_sensitive(report_path, 'path')}"
            )
        else:
            print_info_debug(
                f"[dns-resolver] failed to persist resolution report "
                f"{mark_sensitive(report_path, 'path')}"
            )
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[dns-resolver] report persistence error: {exc}")
