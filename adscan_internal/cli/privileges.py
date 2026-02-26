"""CLI helpers for privilege enumeration commands."""

from __future__ import annotations

from typing import Any
import os
import shlex

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_verbose,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.workspaces import domain_subpath
from rich.prompt import Confirm


def run_enum_all_user_privs(shell: Any, args: str | None) -> None:
    """Run enum_all_user_privs for all users in a domain.

    This extracts the logic from do_enum_all_user_privs so orchestration
    can live outside ``adscan.py``.
    """
    if not args:
        print_error("You must specify a domain. Usage: enum_all_privs <domain>")
        return

    domain = args.strip()

    # Verify that the domain exists in domains_data
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"The domain {marked_domain} is not in the database.")
        return

    marked_domain = mark_sensitive(domain, "domain")
    print_success(f"Enumerating privileges of all users in domain {marked_domain}")

    # Check if credentials are stored
    if (
        "credentials" not in shell.domains_data[domain]
        or not shell.domains_data[domain]["credentials"]
    ):
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No credentials stored for domain {marked_domain}")
        return

    auto = Confirm.ask("Do you want to perform automatic enumeration", default=False)

    # Iterate over each user and their credentials
    for username, credential in shell.domains_data[domain]["credentials"].items():
        # Check if the credential is a hash or a password
        if shell.is_hash(credential):
            marked_username = mark_sensitive(username, "user")
            print_error(
                f"Skipping user {marked_username} - has a hash instead of a password"
            )
            continue

        # Call ask_for_user_privs for each user
        if not auto:
            auto = Confirm.ask(
                "Do you want to switch to automatic enumeration", default=False
            )
        shell.ask_for_user_privs(domain, username, credential, auto)


def run_netexec_user_privs(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
) -> None:
    """Enumerate user privileges across multiple services using NetExec."""
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} not found.")
        return

    services = ["smb", "winrm", "rdp", "mssql"]

    marked_username = mark_sensitive(username, "user")
    marked_domain = mark_sensitive(domain, "domain")
    response = Confirm.ask(
        "Do you want to enumerate privileges for user "
        f"{marked_username} on various services on hosts? "
        f"(⚠ WARNING: This will saturate the network if the number of hosts in domain {marked_domain} is very high)"
    )
    if not response:
        return

    for service in services:
        # Only scan this service if its directory exists in current path.
        if not os.path.exists(os.path.join(service, "ips.txt")):
            print_info_verbose(
                f"Skipping service {service} because the service is not available"
            )
            continue
        try:
            workspace_cwd = (
                shell._get_workspace_cwd()  # type: ignore[attr-defined]
                if hasattr(shell, "_get_workspace_cwd")
                else getattr(shell, "current_workspace_dir", os.getcwd())
            )
            domains_dir = getattr(shell, "domains_dir", "domains")

            targets: str | None = None
            cleaned_hosts = [
                h.strip() for h in (hosts or []) if isinstance(h, str) and h.strip()
            ]
            if cleaned_hosts:
                if len(cleaned_hosts) == 1:
                    targets = cleaned_hosts[0]
                else:
                    tmp_dir = domain_subpath(workspace_cwd, domains_dir, domain, "tmp")
                    os.makedirs(tmp_dir, exist_ok=True)
                    targets_path = os.path.join(
                        tmp_dir, f"hosts.{service}.{username}.txt"
                    )
                    with open(targets_path, "w", encoding="utf-8") as handle:
                        for entry in sorted(set(cleaned_hosts), key=str.lower):
                            handle.write(entry + "\n")
                    targets = targets_path
            else:
                default_hosts_file = domain_subpath(
                    workspace_cwd, domains_dir, domain, "enabled_computers_ips.txt"
                )
                if not os.path.exists(default_hosts_file):
                    continue
                targets = default_hosts_file

            auth_str = shell.build_auth_nxc(username, password, domain, kerberos=False)
            marked_domain = mark_sensitive(domain, "domain")
            marked_username = mark_sensitive(username, "user")
            command = (
                f"{shlex.quote(shell.netexec_path)} {service} {shlex.quote(targets)} {auth_str} "
                f"-t 20 --timeout 30 --log domains/{marked_domain}/{service}/{marked_username}_privs.log"
            )

            print_info(
                f"Starting {service} privilege enumeration for user {marked_username}"
            )
            print_info_verbose(f"Command: {command}")
            shell.run_service_command(command, domain, service, username, password)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Error processing service {service}.")
            print_exception(show_locals=False, exception=exc)


def run_netexec_user_privs_with_orchestration(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
) -> None:
    """Enumerate user privileges with full orchestration (ACEs, delegations, ADCS, shares, spraying)."""
    from rich.prompt import Confirm

    # First, run the basic privilege enumeration
    run_netexec_user_privs(
        shell, domain=domain, username=username, password=password, hosts=hosts
    )

    # Additional orchestration after privilege enumeration
    shell.ask_for_enumerate_user_aces(domain, username, password)

    # Check if the user has Kerberos delegations
    if (
        "delegations" in shell.domains_data[domain]
        and username in shell.domains_data[domain]["delegations"]
    ):
        marked_username = mark_sensitive(username, "user")
        print_warning(f"User {marked_username} has Kerberos delegations configured")
        shell.enum_delegations_user(domain, username, password)

    # Check if there is ADCS in the domain
    if shell.domains_data[domain].get("adcs"):
        marked_username = mark_sensitive(username, "user")
        respuesta_adcs = Confirm.ask(
            f"Do you want to enumerate ADCS privileges for user {marked_username}?"
        )
        if respuesta_adcs:
            run_enum_adcs_privs(
                shell, domain=domain, username=username, password=password
            )

    if not (shell.type == "ctf" and shell.domains_data[domain]["auth"] == "pwned"):
        shell.ask_for_enum_shares(domain, username, password)
    if not (shell.type == "ctf" and shell.domains_data[domain]["auth"] == "pwned"):
        if shell.is_hash(password):
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info_verbose(
                "Skipping password spraying prompt for user "
                f"{marked_username} in domain {marked_domain} because the "
                "credential is a hash."
            )
        else:
            marked_password = mark_sensitive(password, "password")
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            respuesta = Confirm.ask(
                "Do you want to perform a password spraying with the "
                f"{marked_password} password of the user {marked_username} "
                f"in the {marked_domain} domain?"
            )
            if respuesta:
                shell.spraying_with_password(domain, password)
    marked_username = mark_sensitive(username, "user")
    print_success(f"Complete enumeration for user {marked_username}")


def run_enum_adcs_privs(
    shell: Any, *, domain: str, username: str, password: str
) -> None:
    """Enumerate ADCS privileges for a user and prompt for exploitation."""
    from adscan_internal.cli.adcs import ask_for_adcs_esc
    from adscan_internal.services.exploitation import ExploitationService

    try:
        auth = shell.build_auth_certipy(domain, username, password)
        pdc_ip = shell.domains_data[domain].get("pdc")
        if not pdc_ip:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Missing PDC IP for domain {marked_domain}. "
                "Re-run domain initialization or update domain data."
            )
            return

        marked_username = mark_sensitive(username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info(
            f"Enumerating ADCS privileges for user {marked_username} in domain {marked_domain}"
        )

        service = ExploitationService()
        pdc_hostname = shell.domains_data[domain].get("pdc_hostname")
        target_host = None
        if isinstance(pdc_hostname, str) and pdc_hostname.strip():
            target_host = (
                pdc_hostname if "." in pdc_hostname else f"{pdc_hostname}.{domain}"
            )
        output_prefix = None
        domain_dir = shell.domains_data[domain].get("dir")
        if isinstance(domain_dir, str) and domain_dir:
            adcs_dir = os.path.join(domain_dir, "adcs")
            os.makedirs(adcs_dir, exist_ok=True)
            output_prefix = os.path.join(adcs_dir, "certipy_find")
        result = service.adcs.enum_privileges(
            certipy_path=shell.certipy_path,
            pdc_ip=pdc_ip,
            target_host=target_host,
            auth_string=auth,
            output_prefix=output_prefix,
            timeout=300,
            run_command=getattr(shell, "run_command", None),
        )

        if not result.success:
            print_error("Error enumerating ADCS privileges.")
            if result.raw_output:
                print_error(result.raw_output)
            return

        # Process vulnerabilities
        ca_vulns = [v for v in result.vulnerabilities if v.source == "ca"]
        template_vulns = [v for v in result.vulnerabilities if v.source == "template"]

        if ca_vulns:
            marked_username = mark_sensitive(username, "user")
            print_warning(
                f"Vulnerabilities in Certificate Authorities for user {marked_username}:"
            )
            for vuln in sorted(ca_vulns, key=lambda v: int(v.esc_number)):
                shell.console.print(f"   - ESC{vuln.esc_number}")
                ask_for_adcs_esc(
                    shell,
                    domain=domain,
                    esc=vuln.esc_number,
                    username=username,
                    password=password,
                    template=None,
                )
        else:
            marked_username = mark_sensitive(username, "user")
            print_error(
                f"No vulnerabilities found in Certificate Authorities for user {marked_username}"
            )

        if template_vulns:
            for vuln in template_vulns:
                print_warning(
                    f"Vulnerability in template '{vuln.template}': ESC{vuln.esc_number}"
                )
                ask_for_adcs_esc(
                    shell,
                    domain=domain,
                    esc=vuln.esc_number,
                    username=username,
                    password=password,
                    template=vuln.template,
                )
        elif not ca_vulns:
            print_error("No vulnerabilities found in Certificate Templates.")

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error enumerating ADCS.")
        print_exception(show_locals=False, exception=e)


def run_raise_child(shell: Any, *, domain: str, username: str, password: str) -> None:
    """Escalate from child domain to parent domain using raiseChild.py."""
    from adscan_internal.services.exploitation import ExploitationService

    try:
        auth = shell.build_auth_impacket_no_host(username, password, domain)
        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return

        print_info_verbose("Trying to escalate from child domain to parent domain")

        service = ExploitationService()
        result = service.persistence.raise_child(
            impacket_scripts_dir=shell.impacket_scripts_dir,
            auth_string=auth,
            timeout=300,
        )

        if not result.success:
            error_detail = (
                result.raw_output.strip() if result.raw_output else "Unknown error"
            )
            print_error("Error executing raiseChild.py.")
            if error_detail:
                print_error(f"Details: {error_detail}")
            return

        # Process extracted credentials
        for cred in result.credentials:
            marked_username = mark_sensitive(cred["username"], "user")
            marked_nt_hash = mark_sensitive(cred["nt_hash"], "password")
            print_warning(
                f"Credential found - Domain: {cred['domain']}, User: {marked_username}, NT Hash: {marked_nt_hash}"
            )
            shell.add_credential(cred["domain"], cred["username"], cred["nt_hash"])

        print_success("Escalation completed. The credentials have been saved.")

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing raiseChild.")
        print_exception(show_locals=False, exception=e)


def run_enum_cross_domain_acl(shell: Any, *, domain: str) -> None:
    """Enumerate cross-domain ACLs and show options to exploit them."""
    shell.enumerate_user_aces(domain, "", "", cross_domain=True)


def ask_for_enum_cross_domain_acl(shell: Any, *, domain: str) -> None:
    """Ask if you want to attempt to enumerate ACLs from this domain to other domains."""
    # Only prompt if there is at least one other domain configured
    if not any(d != domain for d in shell.domains):
        return

    marked_domain = mark_sensitive(domain, "domain")
    respuesta = Confirm.ask(
        f"Do you want to attempt to enumerate the ACLs from domain {marked_domain} to other domains?"
    )
    if respuesta:
        run_enum_cross_domain_acl(shell, domain=domain)


def ask_for_raise_child(
    shell: Any, *, domain: str, username: str, password: str
) -> None:
    """Ask if you want to attempt to escalate from the child domain to the parent domain."""
    # Only prompt if domain is a subdomain of a configured parent domain
    parts = domain.split(".", 1)
    if len(parts) < 2 or parts[1] not in shell.domains:
        return

    marked_domain = mark_sensitive(domain, "domain")
    respuesta = Confirm.ask(
        f"Do you want to attempt to escalate from the child domain {marked_domain} to the parent domain?"
    )
    if respuesta:
        run_raise_child(shell, domain=domain, username=username, password=password)
    else:
        ask_for_enum_cross_domain_acl(shell, domain=domain)


def run_raise_child_command(shell: Any, args: str) -> None:
    """
    Process the command to raise the child domain to the parent domain level.

    Args:
        shell: The shell instance
        args: A string containing the domain, user, and password separated by spaces.

    Usage:
        raise_child <domain> <user> <password>

    The function splits the input string into components, validates the correct number of arguments,
    and then calls the `run_raise_child` function with the provided domain, user, and password.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: raise_child <domain> <user> <password>")
        return
    domain, username, password = args_list
    run_raise_child(shell, domain=domain, username=username, password=password)
