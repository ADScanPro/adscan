"""Enumeration orchestration helpers extracted from adscan.py.

Thin module that centralizes enum-related prompts and flows to keep the
main CLI entrypoint slim. All functions expect the main application
instance (`self`) as first argument.
"""

from __future__ import annotations

import os

from rich.prompt import Confirm, Prompt

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    print_info,
    print_info_verbose,
    print_success,
    print_warning,
    print_error,
    print_exception,
    confirm_operation,
    mark_sensitive,
    ScanProgressTracker,
)


def ask_for_enum_shares(self, domain: str, username: str, password: str) -> None:
    """Prompt user to enumerate SMB shares with authenticated access."""
    pdc = self.domains_data.get(domain, {}).get("pdc", "N/A")

    if confirm_operation(
        operation_name="Authenticated Share Enumeration",
        description="Enumerates all accessible SMB shares and their permissions for the authenticated user",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "Credential Type": "Hash" if self.is_hash(password) else "Password",
        },
        default=True,
        icon="📁",
    ):
        self.netexec_auth_shares(domain, username, password)


def ask_for_found_credentials(self, domain: str) -> None:
    """Prompt to register found credentials for a given domain."""
    user = Prompt.ask("Enter the user for which you have found credentials")
    passwd = Prompt.ask("Enter the possible password for the user", password=True)
    if user != "n" and passwd != "n":
        self.update_domain_data(domain, username=user, password=passwd)
        self.add_credential(domain, user, passwd)


def ask_for_enum_trusts(self, domain: str) -> None:
    """Prompt user to perform domain trust enumeration."""
    self.do_enum_trusts(domain)


def ask_for_enum_domain_auth(self, domain: str) -> None:
    """Prompt user to perform authenticated domain enumeration with BloodHound."""
    self.do_sync_clock_with_pdc(domain)
    if self.auto:
        self.do_enum_domain_auth(domain)
    else:
        pdc = self.domains_data.get(domain, {}).get("pdc", "N/A")
        username = self.domains_data.get(domain, {}).get("username", "N/A")

        if confirm_operation(
            operation_name="Authenticated Domain Enumeration",
            description="Performs BloodHound data collection and comprehensive domain analysis",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Collection": "BloodHound (All objects, ACLs, Sessions)",
                "Phase": "Primary reconnaissance",
            },
            default=True,
            icon="🔬",
            show_panel=True,
        ):
            self.do_enum_domain_auth(domain)


def ask_for_enum_configs(self, domain: str) -> None:
    """Prompt for configuration enumeration."""
    if self.auto:
        do_enum_configs(self, domain)
    else:
        marked_domain = mark_sensitive(domain, "domain")
        respuesta = Confirm.ask(
            f"Do you want to perform configuration enumeration in domain {marked_domain}?",
            default=True,
        )
        if respuesta:
            do_enum_configs(self, domain)


def do_enum_configs(self, domain: str) -> None:
    """Performs configuration enumeration for the domain."""

    username = self.domains_data.get(domain, {}).get("username", "N/A")
    pdc = self.domains_data.get(domain, {}).get("pdc", "N/A")

    tracker = ScanProgressTracker(
        "Domain Configuration Enumeration",
        total_steps=5,
    )
    tracker.start(details={"Domain": domain, "PDC": pdc, "Username": username})

    # Step 1: Relay List Generation
    tracker.start_step(
        "Relay List Generation", details="Identifying relay-vulnerable hosts"
    )
    try:
        self.do_generate_relay_list(domain)
        tracker.complete_step(details="Relay list generated")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Relay list error: {str(e)[:50]}")

    # Step 2: Password Not Required
    tracker.start_step(
        "Password Not Required Check",
        details="Finding accounts with weak password policies",
    )
    try:
        self.do_bloodhound_passnotreq(domain)
        tracker.complete_step(details="Password policy check completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Password check error: {str(e)[:50]}")

    # Step 3: Password Never Expires
    tracker.start_step(
        "Password Never Expires Check",
        details="Finding accounts with non-expiring passwords",
    )
    try:
        self.do_bloodhound_pwdneverexpires(domain)
        tracker.complete_step(details="Password expiry check completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Expiry check error: {str(e)[:50]}")

    # Step 4: Krbtgt Analysis
    tracker.start_step(
        "Krbtgt Account Analysis",
        details="Analyzing krbtgt privileges and exposure",
    )
    try:
        self.do_bloodhound_krbtgt(domain)
        tracker.complete_step(details="Krbtgt analysis completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Krbtgt analysis error: {str(e)[:50]}")

    # Step 5: DC Access Analysis
    tracker.start_step(
        "Domain Controller Access Check",
        details="Checking non-admin DC access paths",
    )
    try:
        self.do_bloodhound_dc_access(domain)
        tracker.complete_step(details="DC access analysis completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"DC access error: {str(e)[:50]}")

    tracker.print_summary()


def execute_generate_relay_list(self, command: str, domain: str) -> None:
    """Executes the command to generate a relay list."""
    try:
        completed_process = self._run_netexec(command, domain=domain, timeout=300)
        errors = completed_process.stderr
        if completed_process.returncode == 0:
            marked_domain = mark_sensitive(domain, "domain")
            print_info_verbose(f"Relay list generated in domain {marked_domain}")
            relay_file = os.path.join(
                self.domains_dir, domain, "smb", "relay_targets.txt"
            )

            # Check if the file exists before opening it
            if os.path.exists(relay_file):
                try:
                    with open(relay_file, "r", encoding="utf-8") as file:
                        comps = [line.strip() for line in file if line.strip()]
                    count = len(comps)
                    marked_domain = mark_sensitive(domain, "domain")
                    print_success(
                        f"Found a total of {count} computers with unsigned SMB in domain {marked_domain}."
                    )
                    if comps:
                        try:
                            from adscan_internal.services.report_service import (
                                record_technical_finding,
                            )

                            record_technical_finding(
                                self,
                                domain,
                                key="smb_relay_targets",
                                value=comps,
                                details={"count": count},
                                evidence=[
                                    {
                                        "type": "artifact",
                                        "summary": "SMB relay targets list",
                                        "artifact_path": relay_file,
                                    }
                                ],
                            )
                        except Exception as exc:  # pragma: no cover
                            telemetry.capture_exception(exc)
                    if comps:
                        self.update_report_field(domain, "smb_relay_targets", comps)
                    else:
                        current_value = (
                            self.report.get(domain, {})
                            .get("vulnerabilities", {})
                            .get("smb_relay_targets")
                            if getattr(self, "report", None)
                            else None
                        )
                        if current_value in (None, "NS", False):
                            self.update_report_field(domain, "smb_relay_targets", False)
                except Exception as e:  # noqa: BLE001
                    telemetry.capture_exception(e)
                    print_error("Error reading the relay file.")
                    print_exception(show_locals=False, exception=e)
            else:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"No output relay file found for domain {marked_domain}. "
                    "The scan might have found no candidates or failed to write results."
                )
        else:
            print_error("Failed to generate relay list.")
            if errors:
                print_error(errors.strip())
    except Exception as e:  # noqa: BLE001
        telemetry.capture_exception(e)
        print_error("Error generating relay list.")
        print_exception(show_locals=False, exception=e)


def execute_neo4j_config_and_continue(self, cmd: str, domain: str) -> None:
    """Execute legacy Neo4j CLI configuration and continue enumeration."""
    try:
        print_info_verbose(f"Executing Neo4j configuration: {cmd}")
        completed_process = self.run_command(cmd, timeout=300)
        if completed_process.returncode == 0:
            print_success("Neo4j configuration executed successfully.")
            if completed_process.stdout:
                print_info(completed_process.stdout.strip())
        else:
            print_error("Error in neo4j configuration:")
            if completed_process.stderr:
                print_error(completed_process.stderr.strip())
            elif (
                completed_process.stdout
            ):  # Sometimes errors go to stdout for shell commands
                print_error(completed_process.stdout.strip())
    except Exception as e:  # noqa: BLE001
        telemetry.capture_exception(e)
        print_error("Exception executing neo4j configuration.")
        print_exception(show_locals=False, exception=e)

    # Once configuration is finished (or attempted), continue with enumeration
    self.run_enumeration(domain)


def ask_for_enum_cve(self, target_domain: str) -> None:
    """Prompt user to enumerate CVE vulnerabilities."""
    if self.auto:
        self.do_enum_cve_dcs(target_domain)
        if self.type == "audit":
            self.do_enum_cve_all(target_domain)
    else:
        pdc = self.domains_data.get(target_domain, {}).get("pdc", "N/A")
        username = self.domains_data.get(target_domain, {}).get("username", "N/A")
        cves_to_check = "Zerologon, NoPac" if username != "N/A" else "Zerologon"

        if confirm_operation(
            operation_name="CVE Enumeration",
            description="Scans for known vulnerabilities (Zerologon, NoPac) on domain controllers",
            context={
                "Domain": target_domain,
                "PDC": pdc,
                "Username": username,
                "CVEs": cves_to_check,
            },
            default=True,
            icon="🐛",
            show_panel=True,
        ):
            if self.type == "ctf":
                # CTF mode: only enumerate DCs to save time
                self.do_enum_cve_dcs(target_domain)
            else:
                # Show menu for scope selection
                menu_idx = self._questionary_select(
                    f"Select CVE enumeration scope for {target_domain}",
                    options=[
                        "Domain Controllers only",
                        "All domain hosts",
                        "Cancel",
                    ],
                    default_idx=0,
                )
                if menu_idx is None or menu_idx == 2:
                    print_info("CVE enumeration cancelled by user.")
                    return
                if menu_idx == 0:
                    self.do_enum_cve_dcs(target_domain)
                elif menu_idx == 1:
                    self.do_enum_cve_dcs(target_domain)
                    self.do_enum_cve_all(target_domain)


def ask_for_enum_cve_takeover(self, target_domain: str) -> None:
    """Prompt user to scan DCs for high-impact takeover CVEs.

    This is intended for early phases where we want a fast answer to:
    "Is there a direct, critical path to domain takeover via a known DC CVE?"

    It is deliberately narrower than `ask_for_enum_cve`:
    - Scope is always Domain Controllers (no "all hosts" scan)
    - CVEs: Zerologon (+ NoPac when credentials exist)
    """
    if self.domains_data[target_domain]["auth"] == "pwned":
        return

    domain_credentials = self.domains_data.get(target_domain, {})
    username = domain_credentials.get("username")
    password = domain_credentials.get("password")

    cves_to_check = "Zerologon, NoPac" if username and password else "Zerologon"
    pdc = self.domains_data.get(target_domain, {}).get("pdc", "N/A")

    if self.auto:
        self.do_enum_cve_dcs(target_domain)
        return

    if confirm_operation(
        operation_name="CVE Takeover Scan",
        description=(
            "Scans domain controllers for high-impact takeover CVEs "
            "(Zerologon, and NoPac when credentials exist)"
        ),
        context={
            "Domain": target_domain,
            "PDC": pdc,
            "Username": username if username else "N/A (Anonymous)",
            "Target": "Domain Controllers",
            "CVEs": cves_to_check,
        },
        default=True,
        icon="🧨",
        show_panel=True,
    ):
        self.do_enum_cve_dcs(target_domain)
