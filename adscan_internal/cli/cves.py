"""NetExec-based CVE enumeration helpers for the CLI.

These helpers keep NetExec CVE orchestration out of the monolithic
`adscan.py` while still relying on the same execution primitives owned by
the interactive shell.
"""

from __future__ import annotations

from typing import Any
import os
import shlex

from adscan_internal import print_error, print_info, print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.workspaces.computers import (
    count_target_file_entries,
    consume_service_targeting_fallback_notice,
    resolve_domain_service_scope_preference,
    resolve_domain_service_target_file,
)


def run_netexec_cve_dcs(shell: Any, *, cve: str, target_domain: str) -> None:
    """Run a NetExec CVE module against domain controllers of a domain."""
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    auth = shell.build_auth_nxc(
        shell.domains_data[shell.domain]["username"],
        shell.domains_data[shell.domain]["password"],
        shell.domain,
        kerberos=False,
    )
    command = (
        "echo 'y' | "
        f"{shell.netexec_path} smb domains/{target_domain}/dcs.txt {auth} "
        f"--log domains/{target_domain}/smb/{cve}.log -M {cve}"
    )
    marked_target_domain = mark_sensitive(target_domain, "domain")
    print_info(f"Checking for {cve} on domain controllers of {marked_target_domain}")
    print_info_debug(f"Command: {command}")
    shell.execute_netexec_cve_dcs(command, target_domain, cve)


def run_netexec_cve_all(shell: Any, *, cve: str, target_domain: str) -> None:
    """Run a NetExec CVE module against all enabled computers in a domain."""
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    # Initialize auth based on available credentials for the target domain.
    domain_credentials = shell.domains_data.get(target_domain, {})
    username = domain_credentials.get("username")
    password = domain_credentials.get("password")

    if username and password:
        auth = shell.build_auth_nxc(username, password, target_domain, kerberos=False)
    else:
        auth = shell.build_auth_nxc(
            shell.domains_data[shell.domain]["username"],
            shell.domains_data[shell.domain]["password"],
            shell.domain,
        )

    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    domains_dir = getattr(shell, "domains_dir", "domains")
    scope_preference = resolve_domain_service_scope_preference(
        shell,
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=target_domain,
        service="smb",
        domain_data=domain_credentials,
        prompt_title="Choose the target scope for SMB CVE enumeration:",
    )
    targets_file, source = resolve_domain_service_target_file(
        workspace_dir,
        domains_dir,
        target_domain,
        service="smb",
        domain_data=domain_credentials,
        scope_preference=scope_preference,
    )
    if not targets_file:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"No host targets are available for domain {marked_target_domain}."
        )
        return

    command = (
        f"{shell.netexec_path} smb {shlex.quote(targets_file)} "
        f"{auth} -t 20 --timeout 30 --smb-timeout 10 --log domains/{target_domain}/smb/{cve}.log -M {cve}"
    )
    marked_target_domain = mark_sensitive(target_domain, "domain")
    targeting_notice = consume_service_targeting_fallback_notice(
        shell,
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=target_domain,
        service="smb",
        source=source,
    )
    if targeting_notice:
        print_info(targeting_notice)
    print_info(f"Checking for {cve} on all hosts in domain {marked_target_domain}")
    print_info_debug(
        f"[cves] using domain target file source={source} "
        f"for {marked_target_domain}: {mark_sensitive(targets_file, 'path')}"
    )
    print_info(
        f"SMB CVE scope: {mark_sensitive(source, 'detail')} "
        f"({count_target_file_entries(targets_file)} target(s))"
    )
    print_info_debug(f"Command: {command}")

    if cve == "coerce_plus":
        shell.execute_netexec_cve_all_coerce(command, target_domain)
    else:
        shell.execute_netexec_cve_all(command, target_domain, cve)


def run_enum_cve_dcs(shell: Any, *, target_domain: str) -> None:
    """Enumerate CVEs on domain controllers for a specified domain.

    This function checks if the current domain matches the target domain. If it does, it enumerates
    the 'nopac' CVE on domain controllers. It also enumerates the 'zerologon' CVE regardless of
    whether the current domain matches the target domain.

    Args:
        shell: Shell instance with domain data and helper methods.
        target_domain: The domain on which to enumerate CVEs.
    """
    from adscan_internal import print_error, print_operation_header

    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    # Fetch credentials for the target domain (returns {} if domain not found)
    domain_credentials = shell.domains_data.get(target_domain, {})

    # Extract username and password (None if the key doesn't exist or value is falsy)
    username = domain_credentials.get("username")
    password = domain_credentials.get("password")

    pdc = shell.domains_data.get(target_domain, {}).get("pdc", "N/A")
    cves = (
        ["NoPac", "PrintNightmare", "Zerologon"]
        if username and password
        else ["Zerologon"]
    )

    print_operation_header(
        "CVE Enumeration - Domain Controllers",
        details={
            "Domain": target_domain,
            "PDC": pdc,
            "Username": username if username else "N/A (Anonymous)",
            "Target": "Domain Controllers",
            "CVEs": ", ".join(cves),
        },
        icon="🔍",
    )

    shell._init_cve_findings(target_domain=target_domain, scope="dcs")
    # Only build the auth object when both credentials are present and non-empty
    if username and password:
        run_netexec_cve_dcs(shell, cve="nopac", target_domain=target_domain)
        run_netexec_cve_dcs(shell, cve="printnightmare", target_domain=target_domain)
    run_netexec_cve_dcs(shell, cve="zerologon", target_domain=target_domain)

    shell._render_cve_findings_summary(
        target_domain=target_domain,
        title="CVE Findings - Domain Controllers",
        findings=shell._get_cve_findings(target_domain=target_domain, scope="dcs"),
        scope="dcs",
    )
    shell._clear_cve_findings(target_domain=target_domain, scope="dcs")


def run_enum_cve_all(shell: Any, *, target_domain: str) -> None:
    """Enumerate vulnerabilities on all hosts of a domain.

    This function enumerates the following vulnerabilities on all hosts in the specified domain:
    - Spooler
    - WebDAV
    - PrintNightmare
    - MS17-010
    - Coerce+ (DFSCoerce, PetitPotam, and PrinterBug)

    Args:
        shell: Shell instance with domain data and helper methods.
        target_domain: The name of the domain on which to enumerate vulnerabilities.
    """
    from adscan_internal import print_error, print_operation_header

    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    pdc = shell.domains_data.get(target_domain, {}).get("pdc", "N/A")
    username = shell.domains_data.get(target_domain, {}).get("username", "N/A")

    print_operation_header(
        "CVE Enumeration - All Domain Hosts",
        details={
            "Domain": target_domain,
            "PDC": pdc,
            "Username": username,
            "Target": "All Enabled Computers",
            "CVEs": "Spooler, WebDAV, PrintNightmare, MS17-010, Coerce+",
        },
        icon="🔍",
    )

    shell._init_cve_findings(target_domain=target_domain, scope="all")
    run_netexec_cve_all(shell, cve="spooler", target_domain=target_domain)
    run_netexec_cve_all(shell, cve="webdav", target_domain=target_domain)
    run_netexec_cve_all(shell, cve="printnightmare", target_domain=target_domain)
    # run_netexec_cve_all(shell, cve="smbghost", target_domain=target_domain)
    run_netexec_cve_all(shell, cve="ms17-010", target_domain=target_domain)
    run_netexec_cve_all(shell, cve="coerce_plus", target_domain=target_domain)

    shell._render_cve_findings_summary(
        target_domain=target_domain,
        title="CVE Findings - All Hosts",
        findings=shell._get_cve_findings(target_domain=target_domain, scope="all"),
        scope="all",
    )
    shell._clear_cve_findings(target_domain=target_domain, scope="all")


def run_netexec_cve_dcs_from_args(shell: Any, *, args: str) -> None:
    """Execute a netexec command to enumerate vulnerabilities on domain controllers.

    This is a wrapper that parses command-line arguments and delegates to run_netexec_cve_dcs.

    Usage: netexec_cve_dcs <CVE> <domain>

    Args:
        shell: Shell instance with domain data and helper methods.
        args: A string containing the CVE identifier and target domain separated by a space.
              Example: "zerologon example.com"

    Available CVEs:
        zerologon
        nopac
        printnightmare
    """
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return
    args_list = args.split()
    if len(args_list) != 2:
        print_error("Usage: netexec_cve_dcs <CVE> <domain>")
        return
    cve = args_list[0]
    target_domain = args_list[1]
    run_netexec_cve_dcs(shell, cve=cve, target_domain=target_domain)


def run_netexec_cve_all_from_args(shell: Any, *, args: str) -> None:
    """Execute a netexec command to enumerate vulnerabilities on all hosts in the specified domain.

    This is a wrapper that parses command-line arguments and delegates to run_netexec_cve_all.

    Usage: netexec_cve_all <CVE> <domain>

    Args:
        shell: Shell instance with domain data and helper methods.
        args: A string containing the CVE identifier and target domain separated by a space.
              Example: "webdav example.com"

    Available CVEs:
        printnightmare
        webdav
        spooler
        ms17-010
        coerce_plus
    """
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return
    args_list = args.split()
    if len(args_list) != 2:
        print_error("Usage: netexec_cve_all <CVE> <domain>")
        return
    cve = args_list[0]
    target_domain = args_list[1]
    run_netexec_cve_all(shell, cve=cve, target_domain=target_domain)
