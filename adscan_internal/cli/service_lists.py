"""Service list generation (NetExec-based) for the CLI.

These helpers keep host list generation out of the monolithic `adscan.py`,
while still relying on the same execution primitives (`_run_netexec`,
workspace CWD, and retry logic) owned by the shell.
"""

from __future__ import annotations

from typing import Any

import os
import re
import shlex

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_success,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.workspaces import domain_subpath


def netexec_extract_services(shell: Any, *, domain: str) -> None:
    """Extract domain services sequentially (smb/rdp/mssql/winrm)."""
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Generating host lists for different services for domain {marked_domain}"
    )

    shell.netexec_extract_dcs(domain)

    services = ["smb", "rdp", "mssql", "winrm"]
    for service in services:
        try:
            extract_service_for_domain(shell, domain=domain, service=service)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(f"Error extracting hosts for {service}.")
            print_exception(show_locals=False, exception=exc)


def extract_service_for_domain(shell: Any, *, domain: str, service: str) -> None:
    """Extract hosts for a specific service within a domain."""
    hosts_file = os.path.join(service, "ips.txt")

    if not os.path.exists(hosts_file):
        print_info(f"No hosts file exists for service {service}")
        return

    if os.path.getsize(hosts_file) == 0:
        print_info(f"No hosts defined for service {service}")
        return

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    service_path_abs = domain_subpath(workspace_cwd, shell.domains_dir, domain, service)
    os.makedirs(service_path_abs, exist_ok=True)

    marked_domain = mark_sensitive(domain, "domain")
    command = (
        f"{shlex.quote(shell.netexec_path)} {service} {shlex.quote(hosts_file)} "
        f"| grep -F {shlex.quote(marked_domain)}"
    )
    extract_services(shell, command=command, domain=domain, service=service)


def extract_services(shell: Any, *, command: str, domain: str, service: str) -> None:
    """Execute extraction command and update workspace host lists."""
    try:
        proc = shell._run_netexec(command, domain=domain, timeout=300)

        workspace_cwd = shell.current_workspace_dir or os.getcwd()
        service_path = domain_subpath(workspace_cwd, shell.domains_dir, domain, service)
        os.makedirs(service_path, exist_ok=True)

        if proc.returncode != 0:
            return

        output_str = strip_ansi_codes(proc.stdout or "")
        hosts_cap = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", output_str)

        if not hosts_cap:
            marked_domain = mark_sensitive(domain, "domain")
            print_info(
                f"No hosts found for service {service} in domain {marked_domain}"
            )
            return

        hosts_file = os.path.join(service_path, "ips.txt")
        existing_hosts: set[str] = set()
        if os.path.exists(hosts_file):
            with open(hosts_file, "r", encoding="utf-8") as handle:
                existing_hosts = set(line.strip() for line in handle if line.strip())

        new_hosts = set(hosts_cap) - existing_hosts
        if new_hosts:
            with open(hosts_file, "a", encoding="utf-8") as handle:
                for host in sorted(new_hosts):
                    handle.write(f"{host}\n")
            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"Host list updated for domain {marked_domain} with service: {service}"
            )

        if service == "smb" and os.path.exists(service_path):
            shell.ask_for_smb_scan(domain)

    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error(f"Error processing service {service}.")
        print_exception(show_locals=False, exception=exc)
