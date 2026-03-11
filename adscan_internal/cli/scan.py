"""Scan CLI orchestration helpers.

This module extracts scan-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import sys
import time
import traceback
from typing import Any, Protocol

from rich.prompt import Confirm

from adscan_internal import (
    print_domain_info,
    print_error,
    print_error_context,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_instruction,
    print_operation_header,
    print_panel,
    print_results_summary,
    print_scan_status,
    print_warning,
    print_warning_debug,
    telemetry,
)
from adscan_internal.rich_output import (
    mark_passthrough,
    mark_sensitive,
)
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.workspaces import domain_subpath
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.cli.dns import finalize_domain_context
from adscan_internal.cli.nmap import _read_text_file_best_effort


def _format_scan_hosts_arg(hosts: str) -> str:
    """Format hosts argument for NetExec scan command.

    Keep legacy support for host expressions (CIDR, comma-separated values, etc.),
    but protect file-like paths containing spaces.
    """
    value = (hosts or "").strip()
    if not value:
        return value
    if " " in value and (
        "/" in value or "\\" in value or value.endswith((".txt", ".list", ".lst"))
    ):
        return shlex.quote(value)
    return value


def _get_domain_auth_state(self: Any, domain: str) -> str:
    """Return domain auth state with a safe default.

    The start flow can create a domain context with only `pdc` populated before
    the auth state is established. In that case we default to `unauth` so scan
    orchestration does not raise `KeyError('auth')`.
    """
    domain_data = self.domains_data.setdefault(domain, {})
    auth_state = str(domain_data.get("auth", "")).strip().lower()
    if not auth_state:
        auth_state = "unauth"
        domain_data["auth"] = auth_state
        marked_domain = mark_sensitive(domain, "domain")
        print_info_verbose(
            f"Initializing missing auth state for {marked_domain} to '{auth_state}'."
        )
    return auth_state


def ask_for_unauth_scan(self, domain: str) -> None:
    """Prompt user to perform unauthenticated scan for the domain."""
    pdc_ip = self.domains_data.get(domain, {}).get("pdc")
    if pdc_ip:
        finalize_domain_context(
            self,
            domain=domain,
            pdc_ip=pdc_ip,
            interactive=False,
        )
    # Unauthenticated scanning has two valid uses:
    # 1) Start unauth (black-box / no creds): get a first credential quickly, then stop.
    # 2) Start auth (gray-box / creds): optionally run unauth checks too (audit), because
    #    they can reveal additional attack surface even when we are already authenticated.
    #
    # In CTF mode, once we are authenticated/compromised we do not want additional
    # unauth noise, so we skip it entirely.
    current_auth = _get_domain_auth_state(self, domain)
    if self.type == "ctf" and current_auth in ["auth", "pwned"]:
        return

    if self.auto and current_auth not in ["auth", "pwned"]:
        self.do_unauth_scan(domain)
        return

    if not self.auto and current_auth not in ["auth", "pwned"]:
        marked_domain = mark_sensitive(domain, "domain")
        if Confirm.ask(
            f"Do you want to perform an unauthenticated scan for the domain {marked_domain}?",
            default=True,
        ):
            self.do_unauth_scan(domain)
        return

    if self.type == "ctf" and current_auth in ["auth", "pwned"]:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_verbose(
            f"Skipping unauthenticated scan for domain {marked_domain} as it is authenticated."
        )
        return

    if self.type == "audit" and current_auth in ["auth", "pwned"]:
        marked_domain = mark_sensitive(domain, "domain")
        if Confirm.ask(
            f"Do you want to perform an unauthenticated scan for the domain {marked_domain}?",
            default=True,
        ):
            self.do_unauth_scan(domain)


def do_unauth_scan(self, domain: str) -> None:
    """Performs an unauthenticated scan for the specified domain."""
    initial_auth = self.domains_data.get(domain, {}).get("auth")
    pdc_ip = self.domains_data.get(domain, {}).get("pdc")
    if pdc_ip:
        finalize_domain_context(
            self,
            domain=domain,
            pdc_ip=pdc_ip,
            interactive=False,
        )

    # In CTF, once we are authenticated/compromised, avoid additional unauth noise.
    if self.type == "ctf" and initial_auth in ["auth", "pwned"]:
        return

    from adscan_internal.rich_output import ScanProgressTracker

    pdc = self.domains_data.get(domain, {}).get("pdc", "N/A")

    tracker = ScanProgressTracker("Unauthenticated Scan", total_steps=3)
    tracker.start(
        details={
            "Domain": domain,
            "PDC": pdc,
            "Auto Mode": "Enabled" if self.auto else "Interactive",
        }
    )

    tracker.start_step("SMB Service Scan", details="Enumerating SMB shares and hosts")
    try:
        self.ask_for_smb_scan(domain)
        tracker.complete_step(details="SMB enumeration completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"SMB scan error: {str(e)[:50]}")

    if initial_auth not in ["auth", "pwned"] and self.domains_data.get(domain, {}).get(
        "auth"
    ) in ["auth", "pwned"]:
        tracker.print_summary({"stopped_early": True})
        return

    tracker.start_step("LDAP Anonymous Scan", details="Querying LDAP directory")
    try:
        self.ask_for_ldap_scan(domain)
        tracker.complete_step(details="LDAP enumeration completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"LDAP scan error: {str(e)[:50]}")

    if initial_auth not in ["auth", "pwned"] and self.domains_data.get(domain, {}).get(
        "auth"
    ) in ["auth", "pwned"]:
        tracker.print_summary({"stopped_early": True})
        return

    tracker.start_step("Kerberos User Enumeration", details="Enumerating domain users")
    try:
        self.ask_for_kerberos_user_enum(domain)
        tracker.complete_step(details="User enumeration completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Kerberos enum error: {str(e)[:50]}")

    tracker.print_summary()


def ask_for_ldap_scan(self, domain: str) -> None:
    """Prompt user to perform unauthenticated LDAP service scan."""
    if _get_domain_auth_state(self, domain) == "pwned" and self.type == "ctf":
        return
    if self.auto:
        self.do_ldap_anonymous(domain)
    else:
        from adscan_internal.rich_output import confirm_operation

        pdc = self.domains_data.get(domain, {}).get("pdc", "N/A")

        if confirm_operation(
            operation_name="Unauthenticated LDAP Scan",
            description="Queries LDAP directory with anonymous bind to enumerate domain information",
            context={"Domain": domain, "PDC": pdc, "Protocol": "LDAP/389"},
            default=True,
            icon="📂",
        ):
            self.do_ldap_anonymous(domain)


class ScanShell(Protocol):
    """Protocol for shell methods needed by scan functions."""

    netexec_path: str
    current_workspace_dir: str | None
    domains_dir: str
    domains: list[str]
    hosts: str
    type: str
    auto: bool
    lab_provider: str | None
    lab_name: str | None
    lab_name_whitelisted: bool | None
    cracking_dir: str
    ldap_dir: str

    def _run_netexec(self, command: str) -> Any: ...
    def _get_lab_slug(self) -> str | None: ...
    def _is_ctf_domain_pwned(self, domain: str) -> bool: ...
    def consolidate_service_ips(self, service: str) -> None: ...
    def workspace_save(self) -> None: ...
    def ask_for_smb_scan(self, domain: str) -> None: ...
    def ask_for_unauth_scan(self, domain: str) -> None: ...
    def do_check_dns(self, domain: str, ip: str | None = None) -> bool: ...
    def create_sub_workspace_for_domain(self, domain: str) -> None: ...


def run_scan_service(
    shell: ScanShell,
    service: str,
    hosts: str,
    domain: str | None = None,
) -> None:
    """Scan a specific service using netexec.

    This function orchestrates the complete scan workflow including command
    execution, output processing, telemetry tracking, and result consolidation.

    Args:
        shell: The active shell instance with scan capabilities.
        service: Service name to scan (e.g., "smb", "ldap").
        hosts: Target hosts (IP range, single IP, or hostname).
        domain: Optional domain name for authenticated scans.
    """
    try:
        # Determine the log path based on whether a domain is provided or not
        if domain:
            # Ensure that the service directory within the domain exists
            service_dir = os.path.join("domains", domain, service)
            if not os.path.exists(service_dir):
                os.makedirs(service_dir)
            log_path = os.path.join("domains", domain, service, f"{service}_scan.log")
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[scan_service] Domain provided: {marked_domain}, log_path: {log_path}"
            )
        else:
            log_path = f"{service}_scan.log"
            print_info_debug(f"[scan_service] No domain provided, log_path: {log_path}")

        hosts_arg = _format_scan_hosts_arg(hosts)
        command = (
            f"{shlex.quote(shell.netexec_path)} {service} {hosts_arg} "
            f"--log {shlex.quote(log_path)} "
        )

        # Professional scan header
        scan_details = {
            "Service": service.upper(),
            "Target": domain if domain else hosts,
            "Mode": "Authenticated" if domain else "Unauthenticated",
        }
        print_operation_header(
            f"{service.upper()} Scan", details=scan_details, icon="🔍"
        )

        print_info_debug(f"Command: {command}")
        marked_domain = mark_sensitive(domain, "domain") if domain else None
        print_info_debug(
            f"[scan_service] Service: {service}, Hosts: {hosts}, Domain parameter: {marked_domain}"
        )

        # Status indicator
        print_scan_status(service.upper(), "starting")

        # Telemetry: track service scan start
        try:
            properties = {
                "scan_mode": getattr(shell, "scan_mode", None),
                "workspace_type": shell.type,
                "auto_mode": shell.auto,
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            # Use service name in event name (e.g., smb_scan_started, ldap_scan_started)
            telemetry.capture(f"{service}_scan_started", properties)
        except Exception as e:
            telemetry.capture_exception(e)

        # clean_env is now automatically applied by self.run_command for external commands
        completed_process = shell._run_netexec(command)

        # Track if any domain was found during this scan
        domain_found = False

        # Check if command execution failed (returned None)
        if completed_process is None:
            print_scan_status(service.upper(), "failed")
            print_error_context(
                f"Failed to execute {service.upper()} scan command",
                context={
                    "Service": service.upper(),
                    "Target": domain if domain else hosts,
                    "Log Path": log_path,
                },
                suggestions=[
                    "Check that NetExec is properly installed",
                    "Verify network connectivity to target hosts",
                    "Check firewall rules and network access",
                ],
            )
            return

        if completed_process.returncode == 0:
            # Store domains count before processing to detect new domains
            domains_before = (
                set(shell.domains)
                if hasattr(shell, "domains") and shell.domains
                else set()
            )

            for line in completed_process.stdout.splitlines():
                raw_line = line.rstrip("\n")
                cleaned_line = strip_ansi_codes(raw_line)
                line = cleaned_line.strip()
                if line:  # If the line is not empty
                    process_service_output_line(shell, cleaned_line, service)

            # Check if any new domain was found by comparing domain lists
            domains_after = (
                set(shell.domains)
                if hasattr(shell, "domains") and shell.domains
                else set()
            )
            domain_found = len(domains_after) > len(domains_before) or bool(
                domains_after - domains_before
            )
        else:
            print_scan_status(service.upper(), "failed")
            print_error_context(
                f"{service.upper()} scan failed",
                context={
                    "Service": service.upper(),
                    "Target": domain if domain else hosts,
                    "Return Code": completed_process.returncode,
                },
                suggestions=[
                    "Verify target is reachable",
                    "Check credentials if this is an authenticated scan",
                    "Review the log file for detailed error information",
                ],
            )
            if completed_process.stderr:
                print_error(f"Error details: {completed_process.stderr.strip()}")

        # Telemetry: track if no domain was found in this service scan (only for unauthenticated scans without domain parameter)
        if not domain and completed_process.returncode == 0 and not domain_found:
            try:
                properties = {
                    "service": service,
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                }
                properties.update(build_lab_event_fields(shell=shell, include_slug=True))
                telemetry.capture("domain_not_discovered", properties)
            except Exception as e:
                telemetry.capture_exception(e)

        # Scan completion with status
        print_scan_status(service.upper(), "completed")

        # Build results summary
        results = {}

        if domain:
            results["Domain"] = domain
            results["Service"] = service.upper()
            results["Status"] = "Completed"

            # Count discovered hosts
            domain_service_ips = os.path.join(
                shell.domains_dir, domain, service, "ips.txt"
            )
            if os.path.exists(domain_service_ips):
                with open(domain_service_ips, "r", encoding="utf-8") as f:
                    host_count = len([line for line in f if line.strip()])
                    results["Hosts Found"] = host_count

            # Consolidate IPs from all domains for this service
            shell.consolidate_service_ips(service)
        else:
            results["Service"] = service.upper()
            results["Status"] = "Completed"
            results["Domains Found"] = (
                len(shell.domains) if hasattr(shell, "domains") else 0
            )

            # Consolidate IPs from all domains for this service
            shell.consolidate_service_ips(service)

        # Print professional results summary
        print_results_summary(f"{service.upper()} Scan Results", results)

        # UX/UI: Show helpful warning if no domains were discovered in unauthenticated scan
        if not domain and results.get("Domains Found", 0) == 0:
            # Check if workstations were detected
            workstations_found = getattr(shell, '_detected_workstations', [])
            
            if workstations_found:
                workstation_list = "\n".join([f"  • {ws}" for ws in workstations_found[:10]])
                if len(workstations_found) > 10:
                    workstation_list += f"\n  ... and {len(workstations_found) - 10} more"
                
                print_panel(
                    f"[bold]Workstations Detected ({len(workstations_found)} total)[/bold]\n\n"
                    f"{workstation_list}\n\n"
                    "[yellow]These are workstations (non-domain controllers) with NetBIOS names only.[/yellow]\n"
                    "[dim]Workstations don't provide domain information for enumeration.[/dim]",
                    title="[bold]💻 Workstation Detection Summary[/bold]",
                    border_style="yellow",
                    padding=(1, 2),
                )
                
                print_info(
                    "\n[bold]💡 Suggestions:[/bold]\n"
                    "  • Look for domain controllers in the same network segment\n"
                    "  • Try scanning a broader IP range that includes DCs\n"
                    "  • Check if you have the correct network/VLAN access\n"
                    "  • Verify that domain controllers are powered on and accessible"
                )
            
            troubleshooting_tips = [
                "Verify the target hosts are Active Directory domain members",
                "Check that the specified IP range/network is correct",
                "Ensure network connectivity to the target hosts",
                "Verify firewall rules allow SMB traffic (port 445)",
                "Verify DNS SRV queries work (UDP/53 may be blocked; try TCP/53 with dig +tcp)",
                "Try scanning a different subnet or expanding the IP range",
                "Check that target systems are powered on and accessible",
            ]

            print_warning(
                "No domains discovered in the specified host range\n[bold]Suggested next steps:[/bold]",
                panel=True,
                items=troubleshooting_tips,
            )
            url = mark_passthrough("https://adscanpro.com/docs/guides/troubleshooting")
            print_instruction(
                f"For more help, visit: {url}"
            )

        # If the service is SMB, call ask_for_smb_scan for each domain with hosts
        if service == "smb" and domain:
            shell.workspace_save()
            if not shell._is_ctf_domain_pwned(domain):
                shell.ask_for_smb_scan(domain)
        elif service == "smb":
            domains_list = list(shell.domains or [])
            if not domains_list:
                return

            selected_domain = None
            if len(domains_list) == 1:
                selected_domain = domains_list[0]
            else:
                from adscan_internal.cli.dns import select_domain_from_rows

                rows = []
                for domain_name in domains_list:
                    domain_info = (
                        shell.domains_data.get(domain_name, {})
                        if shell.domains_data
                        else {}
                    )
                    methods = domain_info.get("discovery_methods") or []
                    if not isinstance(methods, list):
                        methods = []
                    smb_ips_path = os.path.join(
                        shell.domains_dir, domain_name, "smb", "ips.txt"
                    )
                    candidates_text = _read_text_file_best_effort(smb_ips_path)
                    candidate_count = len(
                        [line for line in candidates_text.splitlines() if line.strip()]
                    )
                    rows.append((domain_name, candidate_count, methods))

                selected_domain = select_domain_from_rows(
                    shell,
                    rows=rows,
                    prompt="Multiple domains discovered. Select one to proceed:",
                    title="[bold]🧩 Domains Discovered[/bold]",
                )
                if not selected_domain:
                    return

            if not selected_domain:
                return

            from adscan_internal.cli.dns import (
                preflight_domain_pdc_from_candidates,
            )

            smb_ips_path = os.path.join(
                shell.domains_dir, selected_domain, "smb", "ips.txt"
            )
            candidates_text = _read_text_file_best_effort(smb_ips_path)
            candidate_ips = [
                line.strip()
                for line in candidates_text.splitlines()
                if line.strip()
            ]

            decision = preflight_domain_pdc_from_candidates(
                shell,
                domain=selected_domain,
                candidate_ips=candidate_ips,
                interactive=bool(sys.stdin.isatty()),
                mode_label="unauth",
            )
            if decision.action == "use" and decision.pdc_ip:
                selected_domain = decision.domain
                shell.domains_data.setdefault(selected_domain, {})["pdc"] = (
                    decision.pdc_ip
                )
                print_panel(
                    "[bold]Discovery Summary[/bold]\n\n"
                    f"Domain: {mark_sensitive(selected_domain, 'domain')}\n"
                    f"PDC/DC: {mark_sensitive(decision.pdc_ip, 'ip')}\n"
                    f"Candidates scanned: {len(candidate_ips)}\n\n"
                    "[dim]Proceeding with unauthenticated enumeration.[/dim]",
                    title="[bold]✅ Ready to Enumerate[/bold]",
                    border_style="green",
                    padding=(1, 2),
                )
            else:
                print_panel(
                    "[bold]Validation Incomplete[/bold]\n\n"
                    f"Domain: {mark_sensitive(selected_domain, 'domain')}\n"
                    f"Candidates scanned: {len(candidate_ips)}\n\n"
                    "[yellow]We couldn't validate a PDC for this domain.[/yellow]\n\n"
                    "[bold]Next:[/bold]\n"
                    "• Provide a DC/DNS IP manually\n"
                    "• Or expand the range and re-run discovery",
                    title="[bold]⚠️  Domain Validation[/bold]",
                    border_style="yellow",
                    padding=(1, 2),
                )

            shell.workspace_save()
            if not shell._is_ctf_domain_pwned(selected_domain):
                shell.ask_for_unauth_scan(selected_domain)

    except Exception as e:
        telemetry.capture_exception(e)
        print_error(f"Error executing the {service} scan.")
        print_exception(show_locals=False, exception=e)
        traceback.print_exc()


def process_service_output_line(
    shell: ScanShell,
    line: str,
    service: str,
) -> None:
    """Process each output line from a service scan.

    This function extracts domain and IP information from NetExec scan output,
    creates domain workspaces when new domains are discovered, and tracks
    discovered hosts.

    Args:
        shell: The active shell instance with scan capabilities.
        line: Raw output line from the scan command.
        service: Service name being scanned.
    """
    try:
        original_line = line
        sanitized_line = strip_ansi_codes(original_line)
        line = sanitized_line.strip()
        # Only process lines that contain host information
        uppercase_service = service.upper()
        if not line.upper().startswith(uppercase_service):
            return

        # Extract domain using regular expression
        domain_match = re.search(r"domain:([^)]+)", line)
        if not domain_match:
            print_info_debug(
                f"[CI][{service}] Skipping line (no 'domain:' token found): {line[:100]}"
            )
            return

        # Extract IP (second column)
        columns = line.split()
        if len(columns) < 2:
            print_info_debug(
                f"[CI][{service}] Skipping line (expected IP as second column): {line}"
            )
            return

        domain = domain_match.group(1).strip().lower()
        ip = columns[1].strip()
        marked_domain = mark_sensitive(domain, "domain")
        marked_ip = mark_sensitive(ip, "ip")

        # Verify that the domain contains a dot to validate that it is a real domain
        if "." not in domain:
            # Track workstations separately for better UX
            if not hasattr(shell, '_detected_workstations'):
                shell._detected_workstations = []
            
            workstation_info = f"{ip} ({domain})"
            if workstation_info not in shell._detected_workstations:
                shell._detected_workstations.append(workstation_info)
            
            # Extract hostname from line if available
            hostname_match = re.search(r"name:([^)]+)", line)
            hostname = hostname_match.group(1).strip() if hostname_match else domain
            
            marked_hostname = mark_sensitive(hostname, "host")
            marked_ip = mark_sensitive(ip, "ip")
            
            # Elegant workstation detection message
            from adscan_internal import print_info_verbose
            print_info_verbose(
                f"[dim]💻[/dim] Workstation detected at [cyan]{marked_ip}[/cyan] "
                f"([yellow]{marked_hostname}[/yellow])\n"
                f"   [dim]→ Not a domain controller (NetBIOS name only: {marked_domain})[/dim]"
            )
            print_info_debug(
                f"[CI][{service}] Skipping workstation without FQDN: {marked_domain} at {marked_ip}"
            )
            return

        # Create necessary directories
        workspace_cwd = shell.current_workspace_dir or os.getcwd()
        domain_path = domain_subpath(workspace_cwd, shell.domains_dir, domain)
        cracking_path = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.cracking_dir
        )
        ldap_path = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.ldap_dir
        )
        domain_service_dir = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, service
        )

        # If it's a new domain, create a sub-workspace
        if not os.path.exists(domain_path):
            # Professional domain discovery notification
            print_domain_info(
                domain=domain,
                pdc=ip,
                additional_info={
                    "Service": service.upper(),
                    "Discovery Method": "Automated Scan",
                },
            )
            marked_domain = mark_sensitive(domain, "domain")
            marked_ip = mark_sensitive(ip, "ip")

            print_info_debug(
                f"[process_service_output] New domain detected: {marked_domain} (IP: {marked_ip}, service: {service})"
            )

            # Telemetry: track domain discovery
            try:
                properties = {
                    "service": service,
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                }
                properties.update(build_lab_event_fields(shell=shell, include_slug=True))
                telemetry.capture("domain_discovered", properties)
            except Exception as e:
                telemetry.capture_exception(e)

            # If hosts is a single IP or /32 network, perform DNS resolution check
            try:
                marked_domain = mark_sensitive(domain, "domain")
                print_info_debug(
                    f"[process_service_output] Checking DNS resolution for domain {marked_domain} (hosts: {shell.hosts})"
                )
                net = ipaddress.ip_network(shell.hosts, strict=False)
                if net.num_addresses == 1:
                    print_info_debug(
                        f"[process_service_output] Single IP detected, checking DNS with IP: {shell.hosts}"
                    )
                    if not shell.do_check_dns(domain, ip=shell.hosts):
                        marked_domain = mark_sensitive(domain, "domain")
                        print_warning_debug(
                            f"[process_service_output] DNS check failed for domain {marked_domain} with IP {shell.hosts}"
                        )
                        return
                else:
                    print_info_debug(
                        "[process_service_output] Network range detected, checking DNS without IP"
                    )
                    if not shell.do_check_dns(domain):
                        marked_domain = mark_sensitive(domain, "domain")
                        print_warning_debug(
                            f"[process_service_output] DNS check failed for domain {marked_domain}"
                        )
                        return
                marked_domain = mark_sensitive(domain, "domain")
                print_info_debug(
                    f"[process_service_output] DNS check passed for domain {marked_domain}"
                )
            except Exception as e:
                telemetry.capture_exception(e)
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error performing DNS resolution check for {marked_domain}: {str(e)}"
                )
                pass
            shell.domains.append(domain)
            # Convert to set and back to list to remove duplicates
            shell.domains = list(set(shell.domains))
            marked_domain = mark_sensitive(domain, "domain")
            shell.create_sub_workspace_for_domain(domain)
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[process_service_output] Created sub-workspace for domain {marked_domain}"
            )
            time.sleep(1)

        for directory in [cracking_path, ldap_path, domain_service_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)

        # Handle the IP file while avoiding duplicates
        ips_file = os.path.join(domain_service_dir, "ips.txt")
        existing_ips = set()

        # Read existing IPs if the file exists
        if os.path.exists(ips_file):
            with open(ips_file, "r", encoding="utf-8") as f:
                existing_ips = set(line.strip() for line in f if line.strip())

        # Only add the IP if it does not exist
        if ip not in existing_ips:
            with open(ips_file, "a", encoding="utf-8") as f:
                f.write(f"{ip}\n")
            marked_ip = mark_sensitive(ip, "ip")
            marked_domain = mark_sensitive(domain, "domain")

    except Exception as e:
        telemetry.capture_exception(e)
        
        # Better error context
        print_error_context(
            f"Failed to process {service.upper()} scan output line",
            context={
                "Service": service.upper(),
                "Line Preview": line[:100] if len(line) > 100 else line,
                "Error Type": type(e).__name__,
            },
            suggestions=[
                "This line may contain unexpected format or special characters",
                "The target may be a workstation instead of a domain controller",
                "Check if the target is responding correctly to SMB requests",
            ]
        )
        print_info_debug(f"Full problematic line: {line}")


def consolidate_service_ips(shell: ScanShell, service: str) -> None:
    """Consolidate IPs from all domains for a specific service.

    Args:
        shell: The active shell instance with workspace and domain data.
        service: Service name to consolidate IPs for.
    """
    try:
        # Create the service directory in the workspace if it does not exist
        workspace_service_dir = os.path.join(shell.current_workspace_dir, service)
        if not os.path.exists(workspace_service_dir):
            os.makedirs(workspace_service_dir)

        # Consolidated IPs file
        consolidated_ips_file = os.path.join(workspace_service_dir, "ips.txt")
        all_ips = set()  # Use a set to avoid duplicates

        # Iterate through all domains
        for domain in shell.domains:
            domain_service_ips = os.path.join(
                shell.domains_dir, domain, service, "ips.txt"
            )
            if os.path.exists(domain_service_ips):
                with open(domain_service_ips, "r", encoding="utf-8") as f:
                    domain_ips = set(line.strip() for line in f if line.strip())
                    all_ips.update(domain_ips)

        # Write all unique IPs to the consolidated file
        if all_ips:
            with open(consolidated_ips_file, "w", encoding="utf-8") as f:
                for ip in sorted(all_ips):  # Sort the IPs for better readability
                    f.write(f"{ip}\n")

    except Exception as e:
        telemetry.capture_exception(e)

        print_error(f"Error consolidating IPs for service {service}.")
        print_exception(show_locals=False, exception=e)


def consolidate_domain_computers(shell: ScanShell, args: Any) -> None:
    """Consolidate the list of computers from all domains.

    Args:
        shell: The active shell instance with workspace and domain data.
        args: Unused argument (kept for compatibility with original signature).
    """
    try:
        # Consolidated computers file
        consolidated_computers_file = os.path.join(
            shell.current_workspace_dir, "enabled_computers_ips.txt"
        )
        all_computers = set()  # Use a set to avoid duplicates

        # Iterate through all domains
        for domain in shell.domains:
            domain_computers_file = os.path.join(
                shell.domains_dir, domain, "enabled_computers_ips.txt"
            )
            if os.path.exists(domain_computers_file):
                with open(domain_computers_file, "r", encoding="utf-8") as f:
                    domain_computers = set(line.strip() for line in f if line.strip())
                    all_computers.update(domain_computers)

        # Write all unique computers to the consolidated file
        if all_computers:
            with open(consolidated_computers_file, "w", encoding="utf-8") as f:
                for computer in sorted(all_computers):
                    f.write(f"{computer}\n")

        # Also consolidate enabled_computers.txt across domains
        consolidated_names_file = os.path.join(
            shell.current_workspace_dir, "enabled_computers.txt"
        )
        all_names = set()
        for domain in shell.domains:
            domain_names_file = os.path.join(
                shell.domains_dir, domain, "enabled_computers.txt"
            )
            if os.path.exists(domain_names_file):
                with open(domain_names_file, "r", encoding="utf-8") as fn:
                    domain_names = set(line.strip() for line in fn if line.strip())
                    all_names.update(domain_names)
        if all_names:
            with open(consolidated_names_file, "w", encoding="utf-8") as f2:
                for name in sorted(all_names):
                    f2.write(f"{name}\n")

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error consolidating computers.")
        print_exception(show_locals=False, exception=e)
