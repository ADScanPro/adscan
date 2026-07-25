"""Bulk DNS resolution for Computer nodes using massdns.

Uses the DC IP as the sole resolver — in a lab or customer engagement the DC
always knows its own A records, so we avoid dependency on external DNS.

massdns is a C binary included in the ADscan runtime. If it is not found the
function falls back gracefully (caller uses ``dnshostname`` directly instead).

This is Phase 2 of the two-phase massdns flow: it runs during attack-graph
collection, annotates each resolved Computer node with its first IPv4 in
memory, and — when an ``output_dir`` is supplied — persists a
``massdns_resolution_report.json`` using the shared report service in
``adscan_internal/services/reachability/massdns_report.py`` (the same schema
Phase 3, ``cli/nmap``, writes and the Kerberos hostname inventory consumes).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from typing import TYPE_CHECKING

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

# Phase 2 writes its massdns side artifacts under distinct filenames so it never
# clobbers the Phase-3-owned files (``enabled_computers_ips.txt``,
# ``massdns_output.jsonl``, ``massdns_hosts.txt``) in the same domain dir. The
# shared report file (``massdns_resolution_report.json``) is intentionally the
# same path both phases use — its schema is identical (C2 builder) and the
# Kerberos hostname inventory reads it from there.
_REPORT_FILENAME = "massdns_resolution_report.json"
_COLLECTOR_RESOLVED_IP_FILENAME = "collector_resolved_ips.txt"
_COLLECTOR_RAW_OUTPUT_FILENAME = "collector_massdns_output.jsonl"


def _find_massdns() -> str | None:
    """Return the massdns binary path or None if not found."""
    found = shutil.which("massdns")
    if found:
        return found
    adscan_home = os.getenv("ADSCAN_HOME") or ""
    for candidate in (
        os.path.join(adscan_home, "bin", "massdns"),
        os.path.join(adscan_home, "tools", "massdns", "bin", "massdns"),
    ):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def _parse_ndjson_a_records_map(path: str) -> dict[str, list[str]]:
    """Parse massdns NDJSON output → hostname (lowered, no trailing dot) → all IPv4s.

    Captures every distinct A record per host, preserving first-seen order so
    the first element is the same IP the single-IP path used to return.
    """
    result: dict[str, list[str]] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                hostname = str(rec.get("name") or "").strip().rstrip(".").lower()
                if not hostname:
                    continue
                data = rec.get("data")
                if not isinstance(data, dict):
                    continue
                ips = result.setdefault(hostname, [])
                for item in data.get("answers") or []:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("type") or "").upper() != "A":
                        continue
                    ip = str(item.get("data") or "").strip()
                    if (
                        ip
                        and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip)
                        and ip not in ips
                    ):
                        ips.append(ip)
    except OSError:
        pass
    return {host: ips for host, ips in result.items() if ips}


def _parse_ndjson_a_map(path: str) -> dict[str, str]:
    """Parse massdns NDJSON output → hostname → first IPv4 (back-compat helper)."""
    return {host: ips[0] for host, ips in _parse_ndjson_a_records_map(path).items()}


def resolve_computer_nodes(
    result: "CollectionResult",
    dc_ip: str,
    *,
    timeout: int = 60,
    output_dir: str | None = None,
    domain: str | None = None,
) -> int:
    """Resolve Computer node hostnames to IPs via massdns.

    Writes ``ip_address`` (the first resolved IPv4) into each resolved Computer
    node's properties. When ``output_dir`` is supplied, also persists a
    ``massdns_resolution_report.json`` (multi-IP, shared schema) plus the
    collector-owned resolved-IP and raw-output side artifacts into that
    directory.

    Args:
        result: The collection result whose Computer nodes are annotated.
        dc_ip: DC IP used as the sole massdns resolver.
        timeout: massdns subprocess timeout in seconds.
        output_dir: Workspace domain dir to persist the report into; when None
            the function behaves exactly as before — in-memory annotation only,
            no file written.
        domain: Domain name stamped into the persisted report context.

    Returns:
        The number of nodes that received an IP.
    """
    computers = [n for n in result.nodes.values() if is_collectable_computer_host(n)]
    hostnames = [
        str(n.properties.get("dnshostname") or "").strip().lower() for n in computers
    ]
    hostnames = [h for h in hostnames if h]
    if not hostnames:
        return 0

    massdns_bin = _find_massdns()
    if not massdns_bin:
        print_info_debug("[dns-resolver] massdns not found — skipping IP resolution")
        return 0

    resolved = 0
    with tempfile.TemporaryDirectory(prefix="adscan_dns_") as tmpdir:
        hosts_file = os.path.join(tmpdir, "hosts.txt")
        output_file = os.path.join(tmpdir, "out.jsonl")
        resolver_file = os.path.join(tmpdir, "resolvers.txt")

        with open(hosts_file, "w") as fh:
            fh.write("\n".join(hostnames) + "\n")
        with open(resolver_file, "w") as fh:
            fh.write(dc_ip + "\n")

        cmd = (
            f"{shlex.quote(massdns_bin)} -r {shlex.quote(resolver_file)} "
            f"-t A -o J -w {shlex.quote(output_file)} {shlex.quote(hosts_file)}"
        )
        print_info_verbose(f"[dns-resolver] resolving {len(hostnames)} hostnames")
        try:
            subprocess.run(
                cmd,
                shell=True,
                timeout=timeout,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            print_info_debug("[dns-resolver] massdns timed out")
            return 0
        except OSError as exc:
            print_info_debug(f"[dns-resolver] massdns execution error: {exc}")
            return 0

        host_to_ips = _parse_ndjson_a_records_map(output_file)

    for node in computers:
        dns = str(node.properties.get("dnshostname") or "").strip().lower()
        if not dns:
            continue
        ips = host_to_ips.get(dns)
        if ips:
            node.properties["ip_address"] = ips[0]
            resolved += 1

    print_info_debug(f"[dns-resolver] resolved {resolved}/{len(computers)} computers")

    if output_dir:
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
    """Persist the shared massdns report plus collector-owned side artifacts."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        resolved_ip_file = os.path.join(output_dir, _COLLECTOR_RESOLVED_IP_FILENAME)
        raw_output_file = os.path.join(output_dir, _COLLECTOR_RAW_OUTPUT_FILENAME)
        report_path = os.path.join(output_dir, _REPORT_FILENAME)

        # Flat resolved-IP file (unique, hostname/input order preserved).
        unique_ips: list[str] = []
        seen_ips: set[str] = set()
        raw_lines: list[str] = []
        for hostname in hostnames:
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
            hostnames=hostnames,
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
