"""Workspace data loading functionality.

This module handles loading workspace variables from JSON files and applying
them to the CLI shell instance, including DNS reconfiguration and telemetry updates.
"""

from __future__ import annotations

import json
import os
import time
import ipaddress
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
    print_panel,
    print_info_verbose,
    print_success,
    print_warning,
    print_warning_verbose,
)
from adscan_internal.interaction import is_non_interactive
from rich.prompt import Confirm, Prompt
from adscan_internal.workspaces.io import read_json_file
from adscan_internal.workspaces.state import apply_workspace_variables_to_shell
from adscan_internal.cli.common import build_telemetry_context


def _apply_workspace_name_inference(shell: Any) -> None:
    """Populate lab inference metadata from the workspace name if not already known.

    Runs at workspace load time regardless of whether ``lab_provider`` is already
    set.  The guard is ``lab_inference_source``: if it is already populated (e.g.
    loaded from a persisted ``variables.json`` or set by domain inference in
    ``start.py``), the function does nothing.

    Two cases are handled:

    * **No ``lab_provider``** — fresh/un-inferred workspace: sets provider, name,
      whitelisted flag *and* inference metadata (same as the original inline block).
    * **``lab_provider`` set but ``lab_inference_source`` is None** — existing
      workspace created before this field was persisted: only fills in the inference
      metadata when the inferred provider matches the stored one, so we never
      silently overwrite a manually-configured provider.
    """
    if getattr(shell, "lab_inference_source", None) or getattr(
        shell, "lab_confirmation_state", None
    ) in {"manual", "accepted_inference"}:
        return  # Already known — nothing to do

    workspace_name = str(getattr(shell, "current_workspace", None) or "").strip()
    if not workspace_name or getattr(shell, "type", None) != "ctf":
        return

    try:
        from adscan_core.domain_inference import resolve_lab_from_text  # noqa: PLC0415

        inferred = resolve_lab_from_text(workspace_name)
        if not inferred:
            return

        inferred_provider, inferred_lab, inferred_whitelisted = inferred
        existing_provider = getattr(shell, "lab_provider", None)

        if not existing_provider:
            # Fresh workspace — set lab context and inference metadata.
            shell.lab_provider = inferred_provider
            shell.lab_name = inferred_lab
            shell.lab_name_whitelisted = inferred_whitelisted
            shell.lab_inference_source = "workspace_name"
            shell.lab_inference_confidence = 0.70
            print_info_debug(
                f"[domain_inference] workspace-load name match (new): "
                f"provider={inferred_provider} lab={inferred_lab}"
            )
        elif existing_provider == inferred_provider:
            # Retroactive fill: provider already known, just record how it was inferred.
            shell.lab_inference_source = "workspace_name"
            shell.lab_inference_confidence = 0.70
            print_info_debug(
                f"[domain_inference] workspace-load name match (retroactive): "
                f"provider={inferred_provider} lab={inferred_lab}"
            )
        # If providers differ, leave inference_source as None — origin is ambiguous.
    except Exception:  # noqa: BLE001
        pass


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
    lab_confirmation_state: str | None
    telemetry: bool
    variables: dict[str, Any] | None

    def _clean_netexec_workspaces(self, *, use_sudo_if_needed: bool = True) -> bool: ...
    def do_cd(self, path: str) -> None: ...
    def do_update_resolv_conf(self, domain_pdc: str) -> bool: ...
    def add_to_hosts(self, domain: str) -> None: ...
    def _clean_domain_entries(self, domain: str) -> None: ...
    def _get_dns_discovery_service(self) -> Any: ...


def _capture_workspace_dns_repair_event(
    *,
    shell: WorkspaceLoaderShell,
    event: str,
    result: str,
    reason: str | None = None,
    pdc_changed: bool | None = None,
) -> None:
    """Capture workspace DNS repair telemetry with safe, high-signal fields."""
    properties: dict[str, Any] = {
        "result": result,
        "mode": "workspace_load",
        "interactive": not is_non_interactive(shell=shell),
        "workspace_type": str(getattr(shell, "type", None) or "unknown"),
    }
    if reason is not None:
        properties["reason"] = reason
    if pdc_changed is not None:
        properties["pdc_changed"] = bool(pdc_changed)

    try:
        telemetry.capture(event, properties=properties)
    except Exception:
        # Best-effort telemetry only.
        return


def _restore_hosts_entry_for_domain(
    shell: WorkspaceLoaderShell,
    *,
    domain: str,
    pdc_ip: str,
    pdc_hostname: str | None,
) -> None:
    """Best-effort restore of /etc/hosts entry for a domain after DNS setup."""
    original_pdc_hostname = shell.pdc_hostname
    original_pdc = shell.pdc
    try:
        if pdc_hostname:
            shell.pdc_hostname = pdc_hostname
        shell.pdc = pdc_ip
        shell.add_to_hosts(domain)
    except Exception as exc:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(f"Could not add {marked_domain} to /etc/hosts.")
        print_exception(show_locals=False, exception=exc)
        telemetry.capture_exception(exc)
    finally:
        shell.pdc_hostname = original_pdc_hostname
        shell.pdc = original_pdc


def _refresh_domain_dc_metadata(
    shell: WorkspaceLoaderShell,
    *,
    domain: str,
    pdc_ip: str,
    pdc_hostname: str | None,
) -> None:
    """Refresh `dcs`/`dcs_hostnames` for a domain after resolver updates."""
    from adscan_internal.cli.dns import is_domain_best_effort_mode

    domain_data = shell.domains_data.setdefault(domain, {})
    old_dcs = list(domain_data.get("dcs", [])) if isinstance(domain_data.get("dcs"), list) else []
    old_hosts = (
        list(domain_data.get("dcs_hostnames", []))
        if isinstance(domain_data.get("dcs_hostnames"), list)
        else []
    )

    discovered_ips: list[str] = []
    discovered_hosts: list[str] = []
    dc_ip_to_hostname: dict[str, str] = {}
    if not is_domain_best_effort_mode(shell, domain):
        try:
            service_getter = getattr(shell, "_get_dns_discovery_service", None)
            if callable(service_getter):
                service = service_getter()
                if service is not None and hasattr(service, "discover_domain_controllers"):
                    dc_ips, dc_hostnames, ip_to_host = service.discover_domain_controllers(
                        domain=(domain or "").strip().rstrip("."),
                        pdc_ip=pdc_ip,
                        preferred_ips=[pdc_ip],
                    )
                    if isinstance(dc_ips, list):
                        discovered_ips = [str(ip).strip() for ip in dc_ips if str(ip).strip()]
                    if isinstance(dc_hostnames, list):
                        discovered_hosts = [
                            str(host).strip() for host in dc_hostnames if str(host).strip()
                        ]
                    if isinstance(ip_to_host, dict):
                        dc_ip_to_hostname = {
                            str(k): str(v) for k, v in ip_to_host.items() if str(k).strip()
                        }
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(f"[workspace_load] Failed to refresh DC metadata for {mark_sensitive(domain, 'domain')}: {exc}")
    else:
        print_info_debug(
            f"[workspace_load] Best-effort DNS mode active for {mark_sensitive(domain, 'domain')}; "
            "skipping SRV-based DC metadata refresh"
        )

    dcs: list[str] = []
    for ip_value in discovered_ips:
        if ip_value and ip_value not in dcs:
            dcs.append(ip_value)
    if pdc_ip and pdc_ip not in dcs:
        dcs.insert(0, pdc_ip)
    if not dcs and pdc_ip:
        dcs = [pdc_ip]

    dcs_hostnames: list[str] = []
    for hostname in discovered_hosts:
        short = hostname.split(".")[0].strip().lower()
        if short and short not in dcs_hostnames:
            dcs_hostnames.append(short)
    if pdc_ip in dc_ip_to_hostname:
        short = str(dc_ip_to_hostname[pdc_ip]).split(".")[0].strip().lower()
        if short and short not in dcs_hostnames:
            dcs_hostnames.insert(0, short)
    if pdc_hostname:
        short = str(pdc_hostname).split(".")[0].strip().lower()
        if short and short not in dcs_hostnames:
            dcs_hostnames.insert(0, short)

    domain_data["dcs"] = dcs
    if dcs_hostnames:
        domain_data["dcs_hostnames"] = dcs_hostnames

    if hasattr(shell, "dcs"):
        try:
            setattr(shell, "dcs", list(dcs))
        except Exception:
            pass

    try:
        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        domains_dir_name = str(getattr(shell, "domains_dir", "domains") or "domains")
        if workspace_dir:
            dcs_file = os.path.join(workspace_dir, domains_dir_name, domain, "dcs.txt")
            os.makedirs(os.path.dirname(dcs_file), exist_ok=True)
            with open(dcs_file, "w", encoding="utf-8") as handle:
                for dc_ip in dcs:
                    handle.write(f"{dc_ip}\n")
            print_info_debug(
                "[workspace_load] Updated dcs.txt: "
                f"path={mark_sensitive(dcs_file, 'path')} "
                f"entries={len(dcs)}"
            )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[workspace_load] Failed writing dcs.txt for {mark_sensitive(domain, 'domain')}: {exc}")

    print_info_debug(
        "[workspace_load] Refreshed DC metadata: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"dcs_old={len(old_dcs)} dcs_new={len(dcs)} "
        f"dcs_hostnames_old={len(old_hosts)} dcs_hostnames_new={len(dcs_hostnames)}"
    )


def _restore_saved_domain_dns_context(
    shell: WorkspaceLoaderShell,
    *,
    domain: str,
    pdc_ip: str,
    pdc_hostname: str | None,
) -> bool:
    """Restore persisted DNS runtime state for a loaded workspace domain."""
    from adscan_internal.cli.dns import is_domain_best_effort_mode

    marked_domain = mark_sensitive(domain, "domain")
    domain_data = shell.domains_data.setdefault(domain, {})

    if is_domain_best_effort_mode(shell, domain):
        print_info_debug(
            "[workspace_load] Best-effort DNS mode active for "
            f"{marked_domain}; skipping resolver reconfiguration"
        )
        domain_data["pdc"] = pdc_ip
        if pdc_hostname:
            domain_data["pdc_hostname"] = pdc_hostname
        _refresh_domain_dc_metadata(
            shell,
            domain=domain,
            pdc_ip=pdc_ip,
            pdc_hostname=pdc_hostname,
        )
        _restore_hosts_entry_for_domain(
            shell,
            domain=domain,
            pdc_ip=pdc_ip,
            pdc_hostname=pdc_hostname,
        )
        _capture_workspace_dns_repair_event(
            shell=shell,
            event="workspace_dns_restore_best_effort",
            result="restored",
            reason="best_effort_mode",
        )
        return True

    if shell.do_update_resolv_conf(f"{domain} {pdc_ip}"):
        resolved_pdc_ip = str(getattr(shell, "pdc", "") or pdc_ip)
        resolved_pdc_hostname = (
            str(getattr(shell, "pdc_hostname", "") or "").strip() or pdc_hostname
        )
        domain_data["pdc"] = resolved_pdc_ip
        if resolved_pdc_hostname:
            domain_data["pdc_hostname"] = resolved_pdc_hostname
        _refresh_domain_dc_metadata(
            shell,
            domain=domain,
            pdc_ip=resolved_pdc_ip,
            pdc_hostname=resolved_pdc_hostname,
        )
        _restore_hosts_entry_for_domain(
            shell,
            domain=domain,
            pdc_ip=resolved_pdc_ip,
            pdc_hostname=resolved_pdc_hostname,
        )
        return True

    print_warning(f"Could not configure DNS for domain {marked_domain}")
    _capture_workspace_dns_repair_event(
        shell=shell,
        event="workspace_dns_restore_failed",
        result="failed",
        reason="saved_mapping_unreachable",
    )
    _attempt_workspace_dns_repair_interactive(
        shell,
        domain=domain,
        saved_pdc_ip=pdc_ip,
        saved_pdc_hostname=pdc_hostname,
    )
    return False


def _prompt_updated_dc_ip_for_workspace_domain(domain: str) -> str | None:
    """Prompt for an updated DC/DNS IP while restoring a workspace."""
    while True:
        ip_input = Prompt.ask(
            f"Enter updated DC/DNS IP for {mark_sensitive(domain, 'domain')}",
            default="",
        ).strip()
        if not ip_input:
            return None
        try:
            ipaddress.ip_address(ip_input)
            return ip_input
        except ValueError:
            print_warning(
                f"Invalid IP format: {mark_sensitive(ip_input, 'ip')}. Please enter a valid IPv4 address."
            )


def _attempt_workspace_dns_repair_interactive(
    shell: WorkspaceLoaderShell,
    *,
    domain: str,
    saved_pdc_ip: str,
    saved_pdc_hostname: str | None,
) -> bool:
    """Try interactive DNS repair for stale workspace domain/DC mappings."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_saved_pdc = mark_sensitive(saved_pdc_ip, "ip")
    _capture_workspace_dns_repair_event(
        shell=shell,
        event="workspace_dns_repair_attempted",
        result="attempted",
    )

    if is_non_interactive(shell=shell):
        print_warning(
            f"DNS for {marked_domain} is not currently reachable "
            f"(saved DC/DNS: {marked_saved_pdc})."
        )
        print_info(
            "If the target changed, reconfigure later with:\n"
            f"  update_resolv_conf {domain} <new_dc_ip>\n"
            "Or run `start_unauth` to rediscover DC/PDC."
        )
        _capture_workspace_dns_repair_event(
            shell=shell,
            event="workspace_dns_repair_skipped",
            result="skipped",
            reason="non_interactive",
        )
        return False

    print_panel(
        "[bold yellow]Workspace DNS mapping appears stale.[/bold yellow]\n\n"
        f"Domain: {marked_domain}\n"
        f"Saved DC/DNS IP: {marked_saved_pdc}\n\n"
        "This is common in CTF labs where DC IPs rotate between sessions.\n"
        "You can repair it now or skip (offline mode).\n",
        title="[bold]🧭 Workspace DNS Repair[/bold]",
        border_style="yellow",
        padding=(1, 2),
    )

    if not Confirm.ask(
        "Try to repair DNS mapping now? (recommended)",
        default=True,
    ):
        print_warning(
            f"Continuing without DNS repair for {marked_domain}. "
            "Domain scans may fail until DNS is fixed."
        )
        _capture_workspace_dns_repair_event(
            shell=shell,
            event="workspace_dns_repair_skipped",
            result="skipped",
            reason="user_declined",
        )
        return False

    try:
        from adscan_internal.cli.dns import confirm_domain_pdc_mapping

        def _on_reenter() -> tuple[str, str] | None:
            updated_ip = _prompt_updated_dc_ip_for_workspace_domain(domain)
            if not updated_ip:
                return None
            return domain, updated_ip

        mapping = confirm_domain_pdc_mapping(
            shell,
            domain=domain,
            candidate_ip=saved_pdc_ip,
            interactive=True,
            mode_label="workspace_load",
            on_reenter=_on_reenter,
        )
        if not mapping:
            print_warning(
                f"Skipping DNS repair for {marked_domain}. "
                "You can continue working offline."
            )
            _capture_workspace_dns_repair_event(
                shell=shell,
                event="workspace_dns_repair_skipped",
                result="skipped",
                reason="preflight_fallback",
            )
            return False

        _validated_domain, validated_pdc_ip = mapping
        if not shell.do_update_resolv_conf(f"{domain} {validated_pdc_ip}"):
            print_warning(
                f"Could not repair DNS for {marked_domain} using "
                f"{mark_sensitive(validated_pdc_ip, 'ip')}."
            )
            _capture_workspace_dns_repair_event(
                shell=shell,
                event="workspace_dns_repair_failed",
                result="failed",
                reason="update_resolv_conf_failed",
            )
            return False

        resolved_hostname = (shell.pdc_hostname or "").strip() or saved_pdc_hostname
        shell.domains_data.setdefault(domain, {})["pdc"] = validated_pdc_ip
        if resolved_hostname:
            shell.domains_data.setdefault(domain, {})["pdc_hostname"] = resolved_hostname
        _refresh_domain_dc_metadata(
            shell,
            domain=domain,
            pdc_ip=validated_pdc_ip,
            pdc_hostname=resolved_hostname,
        )
        _restore_hosts_entry_for_domain(
            shell,
            domain=domain,
            pdc_ip=validated_pdc_ip,
            pdc_hostname=resolved_hostname,
        )
        print_success(f"Workspace DNS repaired for {marked_domain}.")
        _capture_workspace_dns_repair_event(
            shell=shell,
            event="workspace_dns_repair_succeeded",
            result="succeeded",
            pdc_changed=(validated_pdc_ip != saved_pdc_ip),
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            f"Interactive DNS repair failed for {marked_domain}. "
            "Continuing without blocking workspace load."
        )
        print_info_debug(f"[workspace_load] DNS repair exception: {exc}")
        _capture_workspace_dns_repair_event(
            shell=shell,
            event="workspace_dns_repair_failed",
            result="failed",
            reason=f"exception:{type(exc).__name__}",
        )
        return False


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

            # Infer lab from workspace name, backfilling inference metadata
            # even for existing workspaces that already have lab_provider set.
            _apply_workspace_name_inference(shell)

            # Update telemetry context
            telemetry_context = build_telemetry_context(
                shell=shell,
                trigger="workspace_load",
            )
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
                    _restore_saved_domain_dns_context(
                        shell,
                        domain=domain,
                        pdc_ip=pdc,
                        pdc_hostname=pdc_hostname,
                    )

            # Check whether the stored myip is still valid on the configured
            # interface.  DHCP may have assigned a new IP after a reboot or
            # VPN reconnect, causing reverse-connection operations to silently
            # fail.  This surfaces the change immediately and auto-corrects it.
            try:
                from adscan_internal.services.myip_staleness import check_and_refresh_myip
                check_and_refresh_myip(shell, context="workspace load")
            except Exception as _myip_exc:
                print_info_debug(f"[workspace_load] myip staleness check failed: {_myip_exc}")

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
