"""Nmap scanning and host/IP conversion utilities.

This module centralizes all functionality related to:
- Hostname to IP address conversion
- IP address to hostname conversion
- Nmap port scanning by domain/services
- Post-processing of nmap scan results
- Host file management (saving hosts to service directories)
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
from typing import Protocol
import json

from rich.prompt import Confirm

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_success_verbose,
    print_warning,
    telemetry,
)
from adscan_internal.cli.target_scope_warning import confirm_large_target_scope
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.workspaces import domain_subpath

NMAP_IMPORTANT_PORTS_SCAN_TIMEOUT_SECONDS = 7200
NMAP_DC_DISCOVERY_LARGE_RANGE_THRESHOLD = 4096


class NmapShell(Protocol):
    """Protocol for shell methods needed by nmap functions."""

    current_workspace_dir: str | None
    domains_dir: str
    smb_dir: str
    winrm_dir: str
    rdp_dir: str
    mssql_dir: str
    ftp_dir: str
    ssh_dir: str
    dns_dir: str
    http_dir: str
    https_dir: str
    ldap_dir: str
    vnc_dir: str
    kerberos_dir: str
    dns: str
    console: any

    def run_command(self, command: str, timeout: int | None = None) -> any: ...
    def consolidate_service_ips(self, service: str) -> None: ...
    def consolidate_domain_computers(self, args: str) -> None: ...
    def ask_for_unauth_scan(self, domain: str) -> None: ...
    def ask_for_smb_scan(self, domain: str) -> None: ...
    def netexec_extract_domains_ldap(self, args: str) -> None: ...
    def _get_dns_discovery_service(self) -> object: ...
    def _get_lab_slug(self) -> str | None: ...


def _confirm_large_dc_discovery_scan(
    shell: NmapShell,
    *,
    hosts: str,
    timeout_seconds: int,
) -> bool:
    """Warn users about very large CIDR ranges before DC discovery scan."""
    return confirm_large_target_scope(
        shell,
        targets=[hosts],
        threshold=NMAP_DC_DISCOVERY_LARGE_RANGE_THRESHOLD,
        title="[bold yellow]⚠️  DC Discovery Scope Warning[/bold yellow]",
        context_label=f"DC discovery scan (timeout safeguard: {timeout_seconds} seconds)",
        recommendation_lines=[
            "Recommendation: narrow the range to likely DC subnets first.",
            "This reduces scan time and network noise significantly.",
        ],
        confirm_prompt="Continue DC discovery scan on this large range?",
        default_confirm=False,
        non_interactive_message=(
            "Non-interactive mode detected. Continuing with timeout safeguard enabled."
        ),
    )


def discover_dc_candidates_with_nmap(
    shell: NmapShell,
    *,
    hosts: str,
    ports: list[int] | None = None,
    output_path: str | None = None,
    timeout_seconds: int = 600,
) -> list[str]:
    """Discover likely DC candidates by scanning AD core ports with Nmap.

    Args:
        shell: Active shell instance with run_command.
        hosts: Target range or hosts string for nmap.
        ports: TCP ports to scan (defaults to 88, 389, 53).
        output_path: Optional path to write the gnmap output.
        timeout_seconds: Timeout for the nmap command.

    Returns:
        List of IPs that have at least one of the target ports open.
    """
    return sorted(
        discover_dc_candidates_with_nmap_details(
            shell,
            hosts=hosts,
            ports=ports,
            output_path=output_path,
            timeout_seconds=timeout_seconds,
        ).keys()
    )


def discover_dc_candidates_with_nmap_details(
    shell: NmapShell,
    *,
    hosts: str,
    ports: list[int] | None = None,
    output_path: str | None = None,
    timeout_seconds: int = 600,
) -> dict[str, set[int]]:
    """Discover likely DC candidates and retain their open-port hints.

    Returns a dictionary keyed by candidate IP with the set of open AD-related
    ports discovered during the lightweight Nmap pass. This lets later domain
    inference skip probes we already know cannot work (for example SMB/445 when
    445 was closed but LDAP/389 was open).
    """
    try:
        if not _confirm_large_dc_discovery_scan(
            shell,
            hosts=hosts,
            timeout_seconds=timeout_seconds,
        ):
            print_warning("DC discovery scan cancelled by user.")
            return {}

        target_ports = ports or [88, 389, 53]
        port_list = ",".join(str(p) for p in target_ports)
        marked_hosts = mark_sensitive(hosts, "host")
        marked_ports = mark_sensitive(port_list, "text")

        if not output_path:
            workspace_dir = shell.current_workspace_dir or os.getcwd()
            output_path = os.path.join(workspace_dir, "dc_candidates.gnmap")

        print_info(
            "Running a lightweight DC candidate scan (Kerberos/LDAP/DNS) "
            f"on {marked_hosts}..."
        )
        print_info_verbose(f"Scanning TCP ports {marked_ports} to identify likely DCs.")

        scan_cmd = (
            f"nmap --open -n -Pn -sS -p{port_list} "
            f"-oG {shlex.quote(output_path)} {shlex.quote(hosts)}"
        )
        print_info_debug(f"[nmap][dc-discovery] {scan_cmd}")
        result = shell.run_command(scan_cmd, timeout=timeout_seconds)
        if result is None:
            print_error("Nmap DC candidate scan did not return a result.")
            return {}

        output_text = (result.stdout or "") + "\n" + (result.stderr or "")
        if _nmap_output_indicates_missing_privileges(output_text):
            sudo_scan_cmd = (
                f"sudo -n nmap --open -n -Pn -sS -p{port_list} "
                f"-oG {shlex.quote(output_path)} {shlex.quote(hosts)}"
            )
            print_warning(
                "Nmap needs elevated privileges for SYN scan; retrying via sudo."
            )
            print_info_debug(f"[nmap][dc-discovery] {sudo_scan_cmd}")
            result = shell.run_command(sudo_scan_cmd, timeout=timeout_seconds)
            if result is None:
                print_error("Nmap DC candidate scan did not return a result.")
                return {}

            output_text = (result.stdout or "") + "\n" + (result.stderr or "")
            if _nmap_output_indicates_missing_privileges(output_text):
                print_warning(
                    "sudo -n failed or is not permitted; falling back to TCP connect scan."
                )
                scan_cmd = (
                    f"nmap --open -n -Pn -sT -p{port_list} "
                    f"-oG {shlex.quote(output_path)} {shlex.quote(hosts)}"
                )
                print_warning(
                    "Nmap still lacks privileges; retrying in TCP connect mode."
                )
                print_info_debug(f"[nmap][dc-discovery] {scan_cmd}")
                result = shell.run_command(scan_cmd, timeout=timeout_seconds)
                if result is None:
                    print_error("Nmap DC candidate scan did not return a result.")
                    return {}

        gnmap_text = _read_text_file_best_effort(output_path)
        open_ports_by_host = _parse_gnmap_open_ports(gnmap_text)
        candidates = sorted(open_ports_by_host.keys())

        print_success(
            f"Discovered {len(candidates)} DC candidate host(s) "
            f"with ports {marked_ports} open."
        )
        return open_ports_by_host
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Failed to run DC candidate discovery with Nmap.")
        print_exception(show_locals=False, exception=exc)
        return {}


def _read_text_file_best_effort(path: str) -> str:
    """Read text file with best-effort error handling.

    Args:
        path: Path to the text file to read.

    Returns:
        File contents as string, or empty string on error.
    """
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
    except Exception:
        return ""
    return ""


def _run_nmap_port_scan_with_timeout_recovery(
    shell: NmapShell,
    *,
    command: str,
    domain: str,
    timeout_seconds: int,
) -> any:
    """Run Nmap port scan and offer timeout recovery UX when applicable.

    If the command fails specifically due to subprocess timeout, the user can
    choose to retry the same scan without timeout limits.
    """
    result = shell.run_command(command, timeout=timeout_seconds)
    if result is not None:
        return result

    last_error = getattr(shell, "_last_run_command_error", None)
    timed_out = (
        isinstance(last_error, tuple)
        and len(last_error) >= 1
        and str(last_error[0]).strip().lower() == "timeout"
    )
    if not timed_out:
        return None

    marked_domain = mark_sensitive(domain, "domain")
    print_warning(
        f"Nmap port scan for domain {marked_domain} timed out after {timeout_seconds} seconds."
    )
    print_info("This is common on very large domains or slow VPN links.")

    is_non_interactive = bool(os.getenv("CI")) or bool(
        getattr(shell, "non_interactive", False)
    )
    if is_non_interactive:
        print_warning("Non-interactive mode detected; skipping retry without timeout.")
        return None

    retry_without_timeout = Confirm.ask(
        "Do you want to retry the same Nmap scan without timeout?",
        default=False,
    )
    if not retry_without_timeout:
        return None

    print_info(
        f"Retrying Nmap port scan for domain {marked_domain} without timeout. "
        "This may take a long time."
    )
    return shell.run_command(command, timeout=None)


def parse_massdns_a_records(output: str) -> list[str]:
    """Parse massdns stdout and return IPv4 addresses from A records.

    Args:
        output: Raw massdns stdout string (simple output format).

    Returns:
        List of IPv4 addresses in the order found.
    """
    if not output:
        return []
    return re.findall(r"\bA\s+(\d{1,3}(?:\.\d{1,3}){3})", output)


def parse_massdns_ndjson_a_records(path: str) -> list[str]:
    """Parse massdns ndjson output file and return IPv4 addresses from A records."""
    if not path or not os.path.exists(path):
        return []
    ips: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                data = record.get("data")
                if not isinstance(data, dict):
                    continue
                answers = data.get("answers")
                if not isinstance(answers, list):
                    continue
                for item in answers:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("type") or "").upper() != "A":
                        continue
                    ip_value = str(item.get("data") or "").strip()
                    if ip_value and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip_value):
                        ips.append(ip_value)
    except OSError:
        return []
    return ips


def _nmap_output_indicates_missing_privileges(output: str) -> bool:
    """Check if nmap output indicates missing root privileges.

    Args:
        output: Nmap command output to check.

    Returns:
        True if output indicates missing privileges, False otherwise.
    """
    lowered = (output or "").lower()
    markers = (
        "requires root privileges",
        "requested a scan type which requires root privileges",
        "you requested a scan type which requires root privileges",
        "failed to open device",
        "couldn't open a raw socket",
        "could not open a raw socket",
        "operation not permitted",
        "permission denied",
        "not permitted",
    )
    return any(marker in lowered for marker in markers)


def _parse_gnmap_open_ports(text: str) -> dict[str, set[int]]:
    """Parse `nmap -oG` output and return open TCP ports per host.

    Args:
        text: Grepable nmap output text.

    Returns:
        Dictionary mapping host IPs to sets of open TCP port numbers.
    """
    results: dict[str, set[int]] = {}
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("Host:"):
            continue
        # Example: Host: 10.10.10.1 ()  Ports: 445/open/tcp//microsoft-ds///, ...
        try:
            host_part, rest_part = line.split("\t", 1)
            host_ip = host_part.split()[1]
        except Exception:
            continue
        if "Ports:" not in rest_part:
            continue
        ports_blob = rest_part.split("Ports:", 1)[1]
        ports: set[int] = set()
        for entry in ports_blob.split(","):
            entry = entry.strip()
            if not entry:
                continue
            fields = entry.split("/")
            if len(fields) < 3:
                continue
            port_str, state, proto = fields[0], fields[1], fields[2]
            if proto != "tcp" or state != "open":
                continue
            try:
                ports.add(int(port_str))
            except ValueError:
                continue
        if ports:
            results[host_ip] = ports
    return results


def save_domain_host_to_file(
    shell: NmapShell, host: str, service_dir: str, domain: str
) -> None:
    """Save the host's IP to the corresponding domain file, avoiding duplicates.

    Args:
        shell: The active shell instance with workspace and domain data.
        host: Host IP address to save.
        service_dir: Service directory name (e.g., "smb", "rdp").
        domain: Domain name.
    """
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    domain_service_dir = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, service_dir
    )

    if not os.path.exists(domain_service_dir):
        os.makedirs(domain_service_dir)

    host_file = os.path.join(domain_service_dir, "ips.txt")

    # Set to store existing hosts
    existing_hosts = set()

    # If the file exists, read the existing hosts
    if os.path.exists(host_file):
        with open(host_file, "r", encoding="utf-8") as f:
            existing_hosts = set(line.strip() for line in f.readlines())

    # If the host is not in the file, add it
    if host not in existing_hosts:
        with open(host_file, "a", encoding="utf-8") as f:
            f.write(f"{host}\n")


def save_host_to_file(shell: NmapShell, host: str, service_dir: str) -> None:
    """Save the host IP to the corresponding file for the service, avoiding duplicates.

    Args:
        shell: The active shell instance with workspace data.
        host: Host IP address to save.
        service_dir: Service directory path.
    """
    if not os.path.exists(service_dir):
        os.makedirs(service_dir)

    host_file = os.path.join(service_dir, "ips.txt")

    # Set to store existing hosts
    existing_hosts = set()

    # If the file exists, read the existing hosts
    if os.path.exists(host_file):
        with open(host_file, "r", encoding="utf-8") as f:
            existing_hosts = set(line.strip() for line in f.readlines())

    # If the host is not in the file, add it
    if host not in existing_hosts:
        with open(host_file, "a", encoding="utf-8") as f:
            f.write(f"{host}\n")


def convert_hostnames_to_ips_and_scan(
    shell: NmapShell,
    domain: str,
    computers_file: str,
    nmap_dir: str,
    *,
    _is_full_adscan_container_runtime: callable | None = None,
    _sudo_validate: callable | None = None,
    verbose_mode: bool = False,
) -> None:
    """Convert hostnames to IP addresses using massdns, write enabled_computers_ips.txt,
    and then execute the port scan.

    Args:
        shell: The active shell instance with workspace and domain data.
        domain: Domain name.
        computers_file: Path to file containing hostnames.
        nmap_dir: Directory for nmap scan output.
        _is_full_adscan_container_runtime: Function to check if running in container.
        _sudo_validate: Function to validate sudo access.
        verbose_mode: Whether verbose mode is enabled.
    """
    ip_file = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "enabled_computers_ips.txt",
    )
    try:
        hostnames = _read_text_file_best_effort(str(computers_file)).splitlines()
        cleaned_hosts = [h.strip() for h in hostnames if h.strip()]
        marked_computers_file = mark_sensitive(str(computers_file), "path")
        print_info_debug(
            f"Loaded {len(cleaned_hosts)} hostnames from {marked_computers_file}."
        )

        domain_data = (
            shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
        )
        resolvers: list[str] = []
        for key in ("dns", "pdc"):
            value = str(domain_data.get(key) or "").strip()
            if value:
                resolvers.append(value)
        for dc in domain_data.get("dcs", []) if isinstance(domain_data, dict) else []:
            dc_value = str(dc or "").strip()
            if dc_value:
                resolvers.append(dc_value)
        resolvers = list(dict.fromkeys(resolvers))
        if not resolvers:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"No DNS resolvers available for {marked_domain}; cannot resolve computers."
            )
            return

        resolvers_file = os.path.join(
            shell.current_workspace_dir or "",
            shell.domains_dir,
            domain,
            "massdns_resolvers.txt",
        )
        hosts_file = os.path.join(
            shell.current_workspace_dir or "",
            shell.domains_dir,
            domain,
            "massdns_hosts.txt",
        )
        with open(resolvers_file, "w", encoding="utf-8") as f:
            for resolver in resolvers:
                f.write(f"{resolver}\n")
        with open(hosts_file, "w", encoding="utf-8") as f:
            for host in cleaned_hosts:
                f.write(f"{host}\n")

        marked_resolvers = mark_sensitive(resolvers_file, "path")
        print_info_debug(
            f"Using massdns resolvers file {marked_resolvers} with {len(resolvers)} resolver(s)."
        )
        if len(resolvers) < 5:
            marked_resolvers_list = [
                mark_sensitive(resolver, "ip") for resolver in resolvers
            ]
            print_info_debug(
                f"massdns resolvers list: {', '.join(marked_resolvers_list)}"
            )
        massdns_bin = shutil.which("massdns")
        if not massdns_bin:
            adscan_home = os.getenv("ADSCAN_HOME") or ""
            candidates = [
                os.path.join(adscan_home, "bin", "massdns"),
                os.path.join(adscan_home, "tools", "massdns", "bin", "massdns"),
            ]
            for candidate in candidates:
                if candidate and os.path.exists(candidate):
                    massdns_bin = candidate
                    break
        if not massdns_bin:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"massdns is not available; cannot resolve computers for {marked_domain}."
            )
            return

        massdns_output = os.path.join(
            shell.current_workspace_dir or "",
            shell.domains_dir,
            domain,
            "massdns_output.jsonl",
        )
        massdns_command = (
            f"{shlex.quote(massdns_bin)} -r {shlex.quote(resolvers_file)} "
            f"-t A -o J -w {shlex.quote(massdns_output)} {shlex.quote(hosts_file)}"
        )
        completed = shell.run_command(massdns_command, timeout=300)
        if completed is None:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Failed to resolve hostnames to IPs for domain {marked_domain} (massdns timeout or execution error)."
            )
            return

        ips = parse_massdns_ndjson_a_records(massdns_output)
        unique_ips = list(dict.fromkeys(ips))
        resolved_count = len(unique_ips)
        total_hosts = len(cleaned_hosts)
        print_success_verbose(
            f"{resolved_count} IPs discovered from hostnames in {marked_computers_file}."
        )
        print_info(
            f"Resolved {resolved_count}/{total_hosts} host(s) into IPs. "
            f"Saved to {mark_sensitive(ip_file, 'path')}."
        )
        if (
            total_hosts == 0
            or resolved_count == 0
            or resolved_count / max(total_hosts, 1) < 0.1
        ):
            from adscan_internal.rich_output import print_panel

            marked_domain = mark_sensitive(domain, "domain")
            panel_lines = [
                "Very few hosts resolved to IP addresses.",
                f"Domain: {marked_domain}",
                f"Resolved: {resolved_count}/{total_hosts}",
                "",
                "Check DNS resolvers, connectivity, or host list quality.",
            ]
            print_panel(
                "\n".join(panel_lines),
                title="DNS Resolution Warning",
                border_style="yellow",
                expand=False,
            )
        print_info_debug(
            f"Resolved {resolved_count} IP(s) out of {total_hosts} host(s)."
        )
        # Write the unique IP addresses to enabled_computers_ips.txt
        with open(ip_file, "w", encoding="utf-8") as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")
        shell.consolidate_domain_computers("")
        ip_count = len(unique_ips)
        user_response = False
        if ip_count > 10:
            marked_domain = mark_sensitive(domain, "domain")
            user_response = Confirm.ask(
                f"Do you want to perform a port scan on some important ports on the computers in domain {marked_domain} (⚠ WARNING: this is really noisy in big domains)?"
            )
        if user_response or ip_count <= 10:
            # Now execute the port scan on the IP file sequentially
            scan_output_path = os.path.join(nmap_dir, "imp_ports_scan")
            try:
                # Pre-create the output file so if we need to run Nmap with sudo,
                # it won't leave root-owned artifacts inside user workspaces.
                os.makedirs(os.path.dirname(scan_output_path), exist_ok=True)
                with open(scan_output_path, "a", encoding="utf-8"):
                    pass
            except Exception:
                # Best-effort; nmap will still run and we can parse stdout as fallback.
                pass

            port_scan_command = (
                f"nmap --open -sS -p21,22,53,80,88,389,443,445,1433,3389,5900,5985 "
                f"-n -Pn -vvv -iL {shlex.quote(str(ip_file))} "
                f"-oN {shlex.quote(str(scan_output_path))} "
                f"-oG {shlex.quote(str(scan_output_path))}.gnmap"
            )
            marked_domain = mark_sensitive(domain, "domain")
            print_info(
                f"Executing port scan in domain {marked_domain} (this might take a while in big domains)..."
            )
            print_info_debug(f"Port scan command: {port_scan_command}")

            completed_scan_process = _run_nmap_port_scan_with_timeout_recovery(
                shell,
                command=port_scan_command,
                domain=domain,
                timeout_seconds=NMAP_IMPORTANT_PORTS_SCAN_TIMEOUT_SECONDS,
            )

            if completed_scan_process is None:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Failed to run Nmap port scan for domain {marked_domain} (timeout or execution error)."
                )
                return

            if completed_scan_process.returncode != 0:
                combined_output = (
                    (completed_scan_process.stdout or "")
                    + "\n"
                    + (completed_scan_process.stderr or "")
                )
                needs_privileges = _nmap_output_indicates_missing_privileges(
                    combined_output
                )
                can_escalate = os.geteuid() != 0 and shutil.which("sudo") is not None
                if needs_privileges and can_escalate:
                    if (
                        _is_full_adscan_container_runtime
                        and _is_full_adscan_container_runtime()
                    ):
                        print_info_debug(
                            "Nmap -sS requires privileges in container runtime; retrying via sudo -n."
                        )
                        privileged_command = f"sudo -n {port_scan_command}"
                        completed_scan_process = _run_nmap_port_scan_with_timeout_recovery(
                            shell,
                            command=privileged_command,
                            domain=domain,
                            timeout_seconds=NMAP_IMPORTANT_PORTS_SCAN_TIMEOUT_SECONDS,
                        )
                    else:
                        print_info_debug(
                            "Nmap -sS requires privileges; retrying via sudo."
                        )
                        if _sudo_validate and not _sudo_validate():
                            marked_domain = mark_sensitive(domain, "domain")
                            print_error(
                                f"Cannot run Nmap -sS port scan for domain {marked_domain} without sudo."
                            )
                            return
                        privileged_command = f"sudo {port_scan_command}"
                        completed_scan_process = _run_nmap_port_scan_with_timeout_recovery(
                            shell,
                            command=privileged_command,
                            domain=domain,
                            timeout_seconds=NMAP_IMPORTANT_PORTS_SCAN_TIMEOUT_SECONDS,
                        )

                    if completed_scan_process is None:
                        marked_domain = mark_sensitive(domain, "domain")
                        print_error(
                            f"Failed to run Nmap port scan for domain {marked_domain} (timeout or execution error)."
                        )
                        return

            if completed_scan_process.returncode == 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_info_verbose(f"Nmap scan stdout for domain {marked_domain}:")
                gnmap_path = f"{scan_output_path}.gnmap"
                gnmap_text = _read_text_file_best_effort(gnmap_path)
                normal_text = _read_text_file_best_effort(scan_output_path)

                open_ports_by_host = _parse_gnmap_open_ports(gnmap_text)
                if not open_ports_by_host:
                    print_info_debug(
                        f"[DEBUG] Nmap completed with rc=0 but no open ports parsed from gnmap (len={len(gnmap_text)})."
                    )
                    if verbose_mode and normal_text:
                        for line in normal_text.splitlines():
                            shell.console.print(line)

                for host_ip, ports in open_ports_by_host.items():
                    if 445 in ports:
                        save_domain_host_to_file(shell, host_ip, shell.smb_dir, domain)
                    if 5985 in ports:
                        save_domain_host_to_file(
                            shell, host_ip, shell.winrm_dir, domain
                        )
                    if 3389 in ports:
                        save_domain_host_to_file(shell, host_ip, shell.rdp_dir, domain)
                    if 1433 in ports:
                        save_domain_host_to_file(
                            shell, host_ip, shell.mssql_dir, domain
                        )
                    if 21 in ports:
                        save_domain_host_to_file(shell, host_ip, shell.ftp_dir, domain)
                    if 22 in ports:
                        save_domain_host_to_file(shell, host_ip, shell.ssh_dir, domain)
                    if 53 in ports:
                        save_domain_host_to_file(shell, host_ip, shell.dns_dir, domain)
                    if 80 in ports:
                        save_domain_host_to_file(shell, host_ip, shell.http_dir, domain)
                    if 443 in ports:
                        save_domain_host_to_file(
                            shell, host_ip, shell.https_dir, domain
                        )
                    if 389 in ports:
                        save_domain_host_to_file(shell, host_ip, shell.ldap_dir, domain)
                    if 5900 in ports:
                        save_domain_host_to_file(shell, host_ip, shell.vnc_dir, domain)
                    if 88 in ports:
                        save_domain_host_to_file(
                            shell, host_ip, shell.kerberos_dir, domain
                        )

                discovered_hosts = len(open_ports_by_host)
                discovered_ports = sum(len(p) for p in open_ports_by_host.values())
                print_success(
                    f"Important port scan for the domain completed (hosts_with_open_ports={discovered_hosts}, open_tcp_ports={discovered_ports})."
                )
                services = [
                    "smb",
                    "rdp",
                    "mssql",
                    "winrm",
                    "ftp",
                    "ssh",
                    "dns",
                    "http",
                    "https",
                    "ldap",
                    "vnc",
                    "kerberos",
                ]
                for service in services:
                    shell.consolidate_service_ips(service)
            else:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(f"Nmap port scan for domain {marked_domain} failed.")
                if completed_scan_process.stderr:
                    print_error(f"Error details: {completed_scan_process.stderr}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during hostname to IP conversion and port scan.")
        print_exception(show_locals=False, exception=e)


def monitor_nmap_domain(shell: NmapShell, proc: any, domain: str) -> None:
    """Monitor nmap process output for domain-specific port scanning.

    This function processes nmap output in real-time, detecting open ports
    and saving hosts to appropriate service directories.

    Args:
        shell: The active shell instance with workspace and domain data.
        proc: Nmap subprocess object with stdout.
        domain: Domain name being scanned.
    """
    ip_regex = re.compile(r"Discovered open port \d+/tcp on (\d+\.\d+\.\d+\.\d+)")
    process_completed = False

    while True:
        line = proc.stdout.readline()
        if not line and proc.poll() is not None:
            if not process_completed:
                print_success("Important port scan for the domain completed.")
                services = ["smb", "rdp", "mssql", "winrm"]
                for service in services:
                    shell.consolidate_service_ips(service)
                process_completed = True
                break

        match = ip_regex.search(line.decode("utf-8"))
        if match:
            host_ip = match.group(1)

            # Port 445/tcp - SMB
            if b"445/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.smb_dir, domain)

            # Port 5985/tcp - WinRM
            elif b"5985/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.winrm_dir, domain)

            # Port 3389/tcp - RDP
            elif b"3389/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.rdp_dir, domain)

            # Port 88/tcp - Kerberos
            elif b"88/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.kerberos_dir, domain)

            # Port 389/tcp - LDAP
            elif b"389/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.ldap_dir, domain)

            # Port 53/tcp - DNS
            elif b"53/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.dns_dir, domain)
                shell.dns = host_ip

            # Port 1433/tcp - MSSQL
            elif b"1433/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.mssql_dir, domain)

            # Port 22/tcp - SSH
            elif b"22/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.ssh_dir, domain)

            # Port 21/tcp - FTP
            elif b"21/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.ftp_dir, domain)

            # Port 5900/tcp - VNC
            elif b"5900/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.vnc_dir, domain)

            # Port 80/tcp - HTTP
            elif b"80/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.http_dir, domain)

            # Port 443/tcp - HTTPS
            elif b"443/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.https_dir, domain)


def monitor_nmap(shell: NmapShell, proc: any) -> None:
    """Monitor nmap process output for general port scanning.

    This function processes nmap output in real-time, detecting open ports
    and saving hosts to appropriate service directories. After completion,
    it triggers domain extraction or SMB scanning if applicable.

    Args:
        shell: The active shell instance with workspace data.
        proc: Nmap subprocess object with stdout.
    """
    ip_regex = re.compile(r"Discovered open port \d+/tcp on (\d+\.\d+\.\d+\.\d+)")
    process_completed = False

    while True:
        line = proc.stdout.readline()
        if not line and proc.poll() is not None:  # Check if the process has ended
            if not process_completed:
                print_success("Important port scan completed.")
                process_completed = True
                dns_hosts_path = os.path.join(shell.dns_dir, "ips.txt")
                smb_hosts_path = os.path.join(shell.smb_dir, "ips.txt")

                if (
                    os.path.exists(dns_hosts_path)
                    and os.path.getsize(dns_hosts_path) > 0
                ):
                    shell.console.print(
                        "[+] Hosts with open DNS found, extracting domain and DCs",
                        style="bold cyan",
                    )
                    shell.netexec_extract_domains_ldap("")
                elif (
                    os.path.exists(smb_hosts_path)
                    and os.path.getsize(smb_hosts_path) > 0
                ):
                    shell.console.print(
                        "[+] Hosts with SMB found, starting tests...",
                        style="bold green",
                    )
                    shell.ask_for_smb_scan("")
                else:
                    print_error("No hosts with SMB found in the scan.")
            break

        # Attempt to extract the host IP from the nmap output
        match = ip_regex.search(line.decode("utf-8"))
        if match:
            host_ip = match.group(1)  # Capture the IP

            # Port 445/tcp - SMB
            if b"445/tcp" in line:
                print_success(f"Port 445/tcp (SMB) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.smb_dir)
            # Port 5985/tcp - WinRM
            elif b"5985/tcp" in line:
                print_success(f"Port 5985/tcp (WinRM) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.winrm_dir)
            # Port 3389/tcp - RDP
            elif b"3389/tcp" in line:
                print_success(f"Port 3389/tcp (RDP) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.rdp_dir)
            # Port 88/tcp - Kerberos
            elif b"88/tcp" in line:
                print_success(f"Port 88/tcp (Kerberos) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.kerberos_dir)
            # Port 389/tcp - LDAP
            elif b"389/tcp" in line:
                print_success(f"Port 389/tcp (LDAP) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.ldap_dir)
            # Port 53/tcp - DNS
            elif b"53/tcp" in line:
                print_success(f"Port 53/tcp (DNS) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.dns_dir)
                shell.dns = host_ip
            # Port 1433/tcp - MSSQL
            elif b"1433/tcp" in line:
                print_success(f"Port 1433/tcp (MSSQL) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.mssql_dir)
            # Port 22/tcp - SSH
            elif b"22/tcp" in line:
                print_success(f"Port 22/tcp (SSH) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.ssh_dir)
            # Port 21/tcp - FTP
            elif b"21/tcp" in line:
                print_success(f"Port 21/tcp (FTP) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.ftp_dir)
            # Port 5900/tcp - VNC
            elif b"5900/tcp" in line:
                print_success(f"Port 5900/tcp (VNC) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.vnc_dir)
            # Port 80/tcp - HTTP
            elif b"80/tcp" in line:
                print_success(f"Port 80/tcp (HTTP) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.http_dir)
            # Port 443/tcp - HTTPS
            elif b"443/tcp" in line:
                print_success(f"Port 443/tcp (HTTPS) open on {host_ip}.")
                save_host_to_file(shell, host_ip, shell.https_dir)
