"""Enumeration orchestration helpers extracted from adscan.py.

Thin module that centralizes enum-related prompts and flows to keep the
main CLI entrypoint slim. All functions expect the main application
instance (`self`) as first argument.
"""

from __future__ import annotations

import os

from rich.prompt import Confirm, Prompt
from rich.table import Table

from adscan_internal import telemetry
from adscan_internal.reporting_compat import handle_optional_report_service_exception
from adscan_internal.rich_output import (
    BRAND_COLORS,
    print_info,
    print_info_list,
    print_info_verbose,
    print_panel,
    print_panel_with_table,
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
        total_steps=12,
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

    # Step 4: Stale Enabled Users
    tracker.start_step(
        "Stale Enabled Users Check",
        details="Finding enabled identities with prolonged inactivity",
    )
    try:
        self.do_bloodhound_stale_enabled_users(domain)
        tracker.complete_step(details="Stale enabled user hygiene check completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Stale user check error: {str(e)[:50]}")

    # Step 5: Tier-0 / High-Value Identity Sprawl
    tracker.start_step(
        "Tier-0 / High-Value Identity Sprawl",
        details="Measuring privileged identity concentration against enabled-user baseline",
    )
    try:
        self.do_bloodhound_tier0_highvalue_sprawl(domain)
        tracker.complete_step(details="Privileged identity concentration assessed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Identity sprawl error: {str(e)[:50]}")

    # Step 6: Krbtgt Analysis
    tracker.start_step(
        "Krbtgt Account Analysis",
        details="Analyzing krbtgt privileges and exposure",
    )
    try:
        self.do_bloodhound_krbtgt(domain)
        tracker.complete_step(details="Krbtgt analysis completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Krbtgt analysis error: {str(e)[:50]}")

    # Step 7: DC Access Analysis
    tracker.start_step(
        "Domain Controller Access Check",
        details="Checking non-admin DC access paths",
    )
    try:
        self.do_bloodhound_dc_access(domain)
        tracker.complete_step(details="DC access analysis completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"DC access error: {str(e)[:50]}")

    # Step 8: LAPS Coverage Fallback
    tracker.start_step(
        "LAPS Coverage Fallback",
        details="Reuses Phase 1 LAPS inventory or regenerates it if missing",
    )
    try:
        from adscan_internal.workspaces import domain_subpath

        workspace_cwd = getattr(self, "current_workspace_dir", None) or os.getcwd()
        with_laps = domain_subpath(
            workspace_cwd, self.domains_dir, domain, "enabled_computers_with_laps.txt"
        )
        without_laps = domain_subpath(
            workspace_cwd,
            self.domains_dir,
            domain,
            "enabled_computers_without_laps.txt",
        )

        if os.path.exists(with_laps) and os.path.exists(without_laps):
            tracker.complete_step(details="Phase 1 LAPS inventory already available")
        else:
            self.do_bloodhound_computers_with_laps(domain)
            self.do_bloodhound_computers_without_laps(domain)
            tracker.complete_step(details="LAPS fallback inventory generated")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"LAPS fallback error: {str(e)[:50]}")

    # Step 9: Password Policy
    tracker.start_step(
        "Password Policy Audit",
        details="Capturing domain password policy from NetExec --pass-pol",
    )
    try:
        self.do_netexec_pass_policy(domain)
        tracker.complete_step(details="Password policy captured")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Password policy error: {str(e)[:50]}")

    # Step 10: Obsolete Operating Systems
    tracker.start_step(
        "Obsolete Operating Systems Audit",
        details="Capturing obsolete hosts from NetExec LDAP obsolete module",
    )
    try:
        self.do_netexec_obsolete(domain)
        tracker.complete_step(details="Obsolete operating system audit completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"Obsolete OS audit error: {str(e)[:50]}")

    # Step 11: LDAP Signing / Channel Binding
    tracker.start_step(
        "LDAP Security Posture Audit",
        details="Capturing LDAP signing and channel binding posture on Domain Controllers",
    )
    try:
        self.do_netexec_ldap_security(domain)
        tracker.complete_step(details="LDAP signing and channel binding posture captured")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"LDAP posture audit error: {str(e)[:50]}")

    # Step 12: SMBv1 Exposure
    tracker.start_step(
        "SMBv1 Exposure Audit",
        details="Capturing hosts that still expose SMBv1 across the selected SMB scope",
    )
    try:
        self.do_netexec_smbv1(domain)
        tracker.complete_step(details="SMBv1 exposure audit completed")
    except Exception as e:  # noqa: BLE001
        tracker.fail_step(details=f"SMBv1 audit error: {str(e)[:50]}")

    tracker.print_summary()


_RELAY_LIST_ENUM_TIMEOUT_SECONDS = 1800


def _is_dc_relay_target(self, domain: str, host: str) -> bool:
    """Return whether a relay target looks like a Domain Controller."""
    candidate = str(host or "").strip().lower()
    if not candidate:
        return False

    if hasattr(self, "is_computer_dc"):
        try:
            return bool(self.is_computer_dc(domain, host))
        except Exception as exc:  # pragma: no cover
            telemetry.capture_exception(exc)

    domain_data = self.domains_data.get(domain, {}) if hasattr(self, "domains_data") else {}
    dc_candidates: set[str] = set()
    for key in ("pdc_hostname", "pdc", "pdc_fqdn"):
        value = str(domain_data.get(key) or "").strip().lower()
        if value:
            dc_candidates.add(value)
    if domain_data.get("dcs"):
        for raw in str(domain_data.get("dcs") or "").split(","):
            value = raw.strip().lower()
            if value:
                dc_candidates.add(value)
    if domain_data.get("dcs_hostnames"):
        for raw in str(domain_data.get("dcs_hostnames") or "").split(","):
            value = raw.strip().lower()
            if value:
                dc_candidates.add(value)

    if candidate in dc_candidates:
        return True
    if "." in candidate and candidate.split(".", 1)[0] in dc_candidates:
        return True
    if f"{candidate}.{domain}".lower() in dc_candidates:
        return True
    return False


def _write_host_list(path: str, hosts: list[str]) -> None:
    """Write one hostname per line to a text artifact."""
    with open(path, "w", encoding="utf-8") as file_handle:
        for host in hosts:
            file_handle.write(host + "\n")


def _render_smb_signing_summary_panel(
    *,
    domain: str,
    total_targets: int,
    dc_targets: list[str],
    non_dc_targets: list[str],
    main_file: str,
    dc_file: str | None,
    non_dc_file: str | None,
) -> None:
    """Render a premium summary for SMB signing-disabled relay targets."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_main_file = mark_sensitive(main_file, "path")
    marked_dc_file = mark_sensitive(dc_file, "path") if dc_file else "N/A"
    marked_non_dc_file = mark_sensitive(non_dc_file, "path") if non_dc_file else "N/A"

    dc_count = len(dc_targets)
    non_dc_count = len(non_dc_targets)
    dc_ratio = (dc_count / total_targets * 100.0) if total_targets else 0.0
    non_dc_ratio = (non_dc_count / total_targets * 100.0) if total_targets else 0.0
    risk_label = (
        "Critical relay posture: Domain Controllers exposed"
        if dc_count
        else "High relay posture: member hosts exposed"
    )
    risk_border = BRAND_COLORS["error"] if dc_count else BRAND_COLORS["warning"]

    print_panel(
        "\n".join(
            [
                f"Domain: {marked_domain}",
                f"Relay posture: {risk_label}",
                f"Unsigned SMB targets: {total_targets}",
                f"Domain Controllers: {dc_count} ({dc_ratio:.1f}%)",
                f"Non-DC hosts: {non_dc_count} ({non_dc_ratio:.1f}%)",
                "",
                "Artifacts",
                f"- Full target list: {marked_main_file}",
                f"- DC subset: {marked_dc_file}",
                f"- Non-DC subset: {marked_non_dc_file}",
            ]
        ),
        title="SMB Signing Exposure Summary",
        border_style=risk_border,
        fit=True,
    )

    table = Table(
        title="SMB Relay Target Breakdown",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Scope", style="cyan")
    table.add_column("Count", justify="right", style="white")
    table.add_column("Risk", style="white")
    table.add_column("Assessment", style="white", max_width=68)
    table.add_row(
        "Domain Controllers",
        str(dc_count),
        "Critical" if dc_count else "None",
        (
            "Unsigned SMB on DCs materially increases relay impact and makes coercion-based "
            "full-domain compromise paths far more realistic."
            if dc_count
            else "No DC exposure identified in the relay target set."
        ),
    )
    table.add_row(
        "Non-DC hosts",
        str(non_dc_count),
        "High" if non_dc_count else "None",
        (
            "Signing-disabled member hosts remain useful relay targets for lateral movement "
            "and credential re-use."
            if non_dc_count
            else "No non-DC relay targets identified."
        ),
    )
    print_panel_with_table(table, border_style=risk_border)

    dc_preview = [mark_sensitive(host, "hostname") for host in dc_targets[:5]]
    non_dc_preview = [mark_sensitive(host, "hostname") for host in non_dc_targets[:5]]
    if dc_preview:
        print_info_list(dc_preview, title=f"DC sample ({dc_count} total)", icon="🖥️")
    if non_dc_preview:
        print_info_list(
            non_dc_preview,
            title=f"Non-DC sample ({non_dc_count} total)",
            icon="💻",
        )


def execute_generate_relay_list(self, command: str, domain: str) -> None:
    """Executes the command to generate a relay list."""
    try:
        completed_process = self._run_netexec(
            command,
            domain=domain,
            timeout=_RELAY_LIST_ENUM_TIMEOUT_SECONDS,
        )
        if not completed_process:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                "Failed to generate relay list: NetExec did not return a result. "
                f"Domain: {marked_domain}"
            )
            return

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
                    dc_targets = [
                        host for host in comps if _is_dc_relay_target(self, domain, host)
                    ]
                    non_dc_targets = [
                        host
                        for host in comps
                        if not _is_dc_relay_target(self, domain, host)
                    ]
                    dc_count = len(dc_targets)
                    non_dc_count = len(non_dc_targets)
                    marked_domain = mark_sensitive(domain, "domain")
                    if count == 0:
                        print_success(
                            f"No unsigned SMB relay targets found in domain {marked_domain}."
                        )
                    elif dc_count > 0:
                        print_warning(
                            f"Found {count} unsigned SMB relay targets in domain {marked_domain}, "
                            f"including {dc_count} Domain Controller"
                            f"{'' if dc_count == 1 else 's'}."
                        )
                    else:
                        print_success(
                            f"Found {count} unsigned SMB relay targets in domain {marked_domain}. "
                            "No Domain Controllers were identified in the target set."
                        )

                    dc_file = None
                    non_dc_file = None
                    if dc_targets:
                        dc_file = os.path.join(
                            self.domains_dir, domain, "smb", "relay_targets_dcs.txt"
                        )
                        _write_host_list(dc_file, dc_targets)
                    if non_dc_targets:
                        non_dc_file = os.path.join(
                            self.domains_dir,
                            domain,
                            "smb",
                            "relay_targets_non_dcs.txt",
                        )
                        _write_host_list(non_dc_file, non_dc_targets)

                    if count:
                        _render_smb_signing_summary_panel(
                            domain=domain,
                            total_targets=count,
                            dc_targets=dc_targets,
                            non_dc_targets=non_dc_targets,
                            main_file=relay_file,
                            dc_file=dc_file,
                            non_dc_file=non_dc_file,
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
                                value={
                                    "all_computers": comps,
                                    "dcs": dc_targets or None,
                                    "non_dcs": non_dc_targets or None,
                                },
                                details={
                                    "count": count,
                                    "domain_controller_count": dc_count,
                                    "non_domain_controller_count": non_dc_count,
                                    "all_computers": comps,
                                    "dcs": dc_targets or None,
                                    "non_dcs": non_dc_targets or None,
                                },
                                evidence=[
                                    {
                                        "type": "artifact",
                                        "summary": "SMB relay targets list",
                                        "artifact_path": relay_file,
                                    },
                                    *(
                                        [
                                            {
                                                "type": "artifact",
                                                "summary": "SMB relay targets - Domain Controllers",
                                                "artifact_path": dc_file,
                                            }
                                        ]
                                        if dc_file
                                        else []
                                    ),
                                    *(
                                        [
                                            {
                                                "type": "artifact",
                                                "summary": "SMB relay targets - Non-DC hosts",
                                                "artifact_path": non_dc_file,
                                            }
                                        ]
                                        if non_dc_file
                                        else []
                                    ),
                                ],
                            )
                        except Exception as exc:  # pragma: no cover
                            if not handle_optional_report_service_exception(
                                exc,
                                action="Technical finding sync",
                                debug_printer=print_info,
                                prefix="[relay-list]",
                            ):
                                telemetry.capture_exception(exc)
                    if comps:
                        self.update_report_field(
                            domain,
                            "smb_relay_targets",
                            {
                                "all_computers": comps,
                                "dcs": dc_targets or None,
                                "non_dcs": non_dc_targets or None,
                            },
                        )
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
