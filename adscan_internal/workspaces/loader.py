"""Workspace data loading functionality.

This module handles loading workspace variables from JSON files and applying
them to the CLI shell instance, including DNS reconfiguration and telemetry updates.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    pass

from adscan_internal import telemetry
from adscan_internal.logging_config import update_workspace_logging
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_warning,
    print_warning_verbose,
)
from adscan_internal.workspaces.io import read_json_file
from adscan_internal.workspaces.state import apply_workspace_variables_to_shell


class WorkspaceLoaderShell(Protocol):
    """Protocol for shell methods needed by load_workspace_data."""

    current_workspace: str | None
    current_workspace_dir: str | None
    current_domain: str | None
    current_domain_dir: str | None
    domain: str | None
    domains: list[str]
    domains_data: dict[str, Any]
    pdc: str | None
    pdc_hostname: str | None
    type: str | None
    lab_provider: str | None
    lab_name: str | None
    lab_name_whitelisted: bool | None
    telemetry: bool
    variables: dict[str, Any] | None

    def _clean_netexec_workspaces(self, *, use_sudo_if_needed: bool = True) -> bool: ...
    def do_cd(self, path: str) -> None: ...
    def do_update_resolv_conf(self, domain_pdc: str) -> bool: ...
    def add_to_hosts(self, domain: str) -> None: ...
    def _clean_domain_entries(self, domain: str) -> None: ...


def load_workspace_data(shell: WorkspaceLoaderShell, workspace_path: str) -> None:
    """Load workspace data (variables and credentials) from JSON files.

    This function:
    1. Cleans NetExec workspaces to avoid schema mismatches
    2. Changes directory context to the workspace
    3. Updates workspace-specific logging
    4. Loads variables from variables.json
    5. Applies variables to the shell instance
    6. Updates telemetry context
    7. Cleans and reconfigures DNS for loaded domains

    Args:
        shell: CLI shell instance that implements WorkspaceLoaderShell protocol
        workspace_path: Absolute path to the workspace directory
    """
    # Clean NetExec workspaces to avoid schema mismatch errors
    shell._clean_netexec_workspaces(use_sudo_if_needed=False)

    print_info(f"Loading workspace data from: {workspace_path}")
    shell.do_cd(workspace_path)  # Change current directory context if necessary

    # Update logging to include workspace-specific log file
    try:
        update_workspace_logging(Path(workspace_path))
        print_info_verbose(
            f"Workspace logging enabled: {workspace_path}/logs/adscan.log"
        )
    except Exception as e:
        # Don't fail workspace loading if logging update fails
        print_info_debug(f"Failed to update workspace logging: {e}")

    variables_file = os.path.join(workspace_path, "variables.json")
    loaded_successfully = True

    # Load variables
    try:
        variables = (
            read_json_file(variables_file) if os.path.exists(variables_file) else None
        )
        if variables is not None:
            apply_workspace_variables_to_shell(shell, variables)

            # Update telemetry context
            telemetry_context: dict[str, object] = {}
            if shell.current_workspace:
                from adscan_internal.telemetry import TELEMETRY_ID

                workspace_unique_id = f"{TELEMETRY_ID}:{shell.current_workspace}"
                telemetry_context["workspace_id_hash"] = hashlib.sha256(
                    workspace_unique_id.encode()
                ).hexdigest()[:12]
            if shell.type:
                telemetry_context["workspace_type"] = shell.type
            if shell.lab_provider:
                telemetry_context["lab_provider"] = shell.lab_provider
            if shell.lab_name and shell.lab_name_whitelisted is True:
                telemetry_context["lab_name"] = shell.lab_name
            if shell.lab_name is not None:
                telemetry_context["lab_name_whitelisted"] = (
                    shell.lab_name_whitelisted is True
                )
            telemetry_context["telemetry_change_trigger"] = "workspace_load"
            telemetry.set_cli_telemetry(
                shell.telemetry, context=telemetry_context
            )  # CLI override set; no identify here

            # Provide known domains to telemetry sanitization for robust filtering.
            domain_candidates: list[str] = []
            if shell.domain:
                domain_candidates.append(shell.domain)
            if shell.domains:
                domain_candidates.extend(shell.domains)
            if shell.domains_data:
                domain_candidates.extend(shell.domains_data.keys())
            telemetry.set_workspace_domains(domain_candidates)
            try:
                enabled_hosts_path = os.path.join(
                    workspace_path, "enabled_computers.txt"
                )
                host_candidates: list[str] = []
                if os.path.exists(enabled_hosts_path):
                    with open(enabled_hosts_path, "r", encoding="utf-8") as handle:
                        for line in handle:
                            value = line.strip()
                            if value:
                                host_candidates.append(value)
                telemetry.set_workspace_hostnames(host_candidates)
            except Exception:
                telemetry.set_workspace_hostnames([])
            try:
                user_candidates: list[str] = []
                password_candidates: list[str] = []
                hostname_candidates: list[str] = []
                base_dn_candidates: list[str] = []
                netbios_candidates: list[str] = []
                domains_dir = os.path.join(workspace_path, "domains")
                for domain in domain_candidates:
                    users_path = os.path.join(domains_dir, domain, "enabled_users.txt")
                    if not os.path.exists(users_path):
                        continue
                    with open(users_path, "r", encoding="utf-8") as handle:
                        for line in handle:
                            value = line.strip()
                            if value:
                                user_candidates.append(value)
                if shell.domains_data:
                    for domain_data in shell.domains_data.values():
                        if not isinstance(domain_data, dict):
                            continue
                        username = domain_data.get("username")
                        if isinstance(username, str) and username:
                            user_candidates.append(username)
                        creds = domain_data.get("credentials")
                        if isinstance(creds, dict):
                            for user_key, pwd_value in creds.items():
                                if isinstance(user_key, str) and user_key:
                                    user_candidates.append(user_key)
                                if isinstance(pwd_value, str) and pwd_value:
                                    password_candidates.append(pwd_value)
                        password_value = domain_data.get("password")
                        if isinstance(password_value, str) and password_value:
                            password_candidates.append(password_value)
                        pdc_hostname = domain_data.get("pdc_hostname")
                        if isinstance(pdc_hostname, str) and pdc_hostname:
                            hostname_candidates.append(pdc_hostname)
                        dcs_hostnames = domain_data.get("dcs_hostnames")
                        if isinstance(dcs_hostnames, list):
                            for host in dcs_hostnames:
                                if isinstance(host, str) and host:
                                    hostname_candidates.append(host)
                        base_dn = domain_data.get("base_dn")
                        if isinstance(base_dn, str) and base_dn:
                            base_dn_candidates.append(base_dn)
                        netbios = domain_data.get("netbios")
                        if isinstance(netbios, str) and netbios:
                            netbios_candidates.append(netbios)
                if isinstance(shell.variables, dict):
                    base_dn = shell.variables.get("base_dn")
                    if isinstance(base_dn, str) and base_dn:
                        base_dn_candidates.append(base_dn)
                spraying_history = (
                    shell.variables.get("password_spraying_history")
                    if isinstance(shell.variables, dict)
                    else None
                )
                if isinstance(spraying_history, dict):
                    for domain_hist in spraying_history.values():
                        if not isinstance(domain_hist, dict):
                            continue
                        password_section = domain_hist.get("password")
                        if not isinstance(password_section, dict):
                            continue
                        passwords_dict = password_section.get("passwords")
                        if isinstance(passwords_dict, dict):
                            for pwd in passwords_dict.keys():
                                if isinstance(pwd, str) and pwd:
                                    password_candidates.append(pwd)
                telemetry.set_workspace_users(user_candidates)
                telemetry.set_workspace_passwords(password_candidates)
                telemetry.set_workspace_base_dns(base_dn_candidates)
                telemetry.set_workspace_netbios(netbios_candidates)
                if hostname_candidates:
                    telemetry.set_workspace_hostnames(
                        host_candidates + hostname_candidates
                    )
            except Exception:
                telemetry.set_workspace_users([])
                telemetry.set_workspace_passwords([])
                telemetry.set_workspace_base_dns([])
                telemetry.set_workspace_netbios([])

            domains_data = variables.get("domains_data")
            if isinstance(domains_data, dict):
                for domain_data in domains_data.values():
                    if isinstance(domain_data, dict):
                        domain_data.pop("credential_previews", None)

            shell.variables = variables  # Store all loaded variables
            print_info(f"Variables loaded from {variables_file}")

            # Refresh attack-graph step support classification for this ADscan version.
            try:
                from adscan_internal.services.attack_graph_service import (
                    refresh_attack_graph_execution_support,
                )

                start = time.monotonic()
                total_changed = 0
                totals: dict[str, int] = {
                    "to_blocked": 0,
                    "to_unsupported": 0,
                    "to_discovered": 0,
                }
                if shell.domains_data:
                    for domain_name in list(shell.domains_data.keys()):
                        counts = refresh_attack_graph_execution_support(shell, domain_name)
                        total_changed += int(counts.get("changed", 0))
                        for key in list(totals.keys()):
                            totals[key] += int(counts.get(key, 0))
                elapsed = round(time.monotonic() - start, 3)
                if total_changed:
                    print_info_debug(
                        "[attack-graph] Refreshed edge execution support: "
                        f"changed={total_changed}, "
                        f"blocked={totals['to_blocked']}, "
                        f"unsupported={totals['to_unsupported']}, "
                        f"discovered={totals['to_discovered']}, "
                        f"elapsed_s={elapsed}"
                    )
                else:
                    print_info_debug(
                        f"[attack-graph] Edge execution support up-to-date (elapsed_s={elapsed})."
                    )
            except Exception as exc:  # pragma: no cover - best effort
                print_info_debug(f"[attack-graph] Refresh failed: {type(exc).__name__}: {exc}")

            # Clean DNS entries for loaded domains to ensure clean state
            # This prevents stale entries from previous sessions with different IPs
            domains_to_clean = []
            if shell.domain:
                domains_to_clean.append(shell.domain)
            if shell.domains:
                domains_to_clean.extend(shell.domains)

            # Also check domains_data for additional domains
            if shell.domains_data:
                for domain_name in shell.domains_data.keys():
                    if domain_name not in domains_to_clean:
                        domains_to_clean.append(domain_name)

            # Clean entries for all domains found in workspace
            if domains_to_clean:
                for domain_to_clean in domains_to_clean:
                    shell._clean_domain_entries(domain_to_clean)

            # Restore unified krb5.conf if present in the workspace root.
            krb5_conf_path = os.path.join(workspace_path, "krb5.conf")
            if os.path.exists(krb5_conf_path):
                os.environ["KRB5_CONFIG"] = krb5_conf_path
                marked_krb5 = mark_sensitive(krb5_conf_path, "path")
                print_info_debug(
                    f"Restored KRB5_CONFIG from workspace krb5.conf: {marked_krb5}"
                )

            # Automatically reconfigure DNS for domains with complete data
            # This ensures the workspace is functional immediately after loading
            domains_to_reconfigure = []

            # Always prefer domains_data to avoid stale top-level values.
            if shell.domains_data:
                for domain_name, domain_info in shell.domains_data.items():
                    if domain_info.get("pdc"):
                        domains_to_reconfigure.append(
                            {
                                "domain": domain_name,
                                "pdc": domain_info.get("pdc"),
                                "pdc_hostname": domain_info.get("pdc_hostname"),
                            }
                        )
            else:
                print_warning_verbose(
                    "No domains_data found in workspace variables; skipping DNS reconfiguration."
                )

            # Reconfigure DNS for each domain with complete data
            if domains_to_reconfigure:
                for domain_info in domains_to_reconfigure:
                    domain = domain_info["domain"]
                    pdc = domain_info["pdc"]
                    pdc_hostname = domain_info.get("pdc_hostname")

                    # Configure the local resolver (Unbound)
                    if shell.do_update_resolv_conf(f"{domain} {pdc}"):
                        # Set pdc_hostname temporarily for add_to_hosts
                        original_pdc_hostname = shell.pdc_hostname
                        original_pdc = shell.pdc

                        if pdc_hostname:
                            shell.pdc_hostname = pdc_hostname
                        shell.pdc = pdc

                        # Add to /etc/hosts
                        try:
                            shell.add_to_hosts(domain)
                        except Exception as e:
                            marked_domain = mark_sensitive(domain, "domain")
                            print_warning(
                                f"Could not add {marked_domain} to /etc/hosts."
                            )
                            print_exception(show_locals=False, exception=e)
                            telemetry.capture_exception(e)

                        # Restore original values
                        shell.pdc_hostname = original_pdc_hostname
                        shell.pdc = original_pdc
                    else:
                        marked_domain = mark_sensitive(domain, "domain")
                        print_warning(
                            f"Could not configure DNS for domain {marked_domain}"
                        )
        else:
            print_warning(
                f"Variables file not found: {variables_file}. Using defaults."
            )
            shell.variables = {}
    except json.JSONDecodeError as e:
        telemetry.capture_exception(e)
        print_error(f"Error decoding JSON from {variables_file}.")
        print_exception(show_locals=False, exception=e)
        loaded_successfully = False
    except OSError as e:
        telemetry.capture_exception(e)
        print_error(f"OS error reading {variables_file}.")
        print_exception(show_locals=False, exception=e)
        loaded_successfully = False
    except Exception as e:
        telemetry.capture_exception(e)
        print_error(f"Unexpected error loading variables from {variables_file}: {e}")
        print_exception(show_locals=False, exception=e)
        loaded_successfully = False

    if loaded_successfully:
        print_success(f"Workspace data successfully processed for {workspace_path}")
    else:
        print_error(
            f"Failed to fully load workspace data from {workspace_path}. Check errors above."
        )


def load_workspace_variables(variables_file: str) -> dict[str, Any] | None:
    """Load workspace variables from a variables.json path.

    Args:
        variables_file: Absolute path to a workspace-level variables.json file.

    Returns:
        Parsed dict if the file exists, otherwise None.

    Raises:
        OSError: On filesystem errors while reading.
        json.JSONDecodeError: If the JSON is malformed.
    """
    if not os.path.exists(variables_file):
        return None
    return read_json_file(variables_file)


def apply_loaded_workspace_variables(shell: Any, variables: dict[str, Any]) -> None:  # type: ignore[type-arg]
    """Apply loaded variables to the CLI shell instance."""
    apply_workspace_variables_to_shell(shell, variables)


__all__ = [
    "apply_loaded_workspace_variables",
    "load_workspace_data",
    "load_workspace_variables",
    "WorkspaceLoaderShell",
]
