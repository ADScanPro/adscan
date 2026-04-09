"""Cleanup helpers for remote Ligolo agent artifacts.

This service centralizes best-effort removal of staged Ligolo agent binaries
from pivot hosts. It is intentionally conservative:

- Cleanup is attempted automatically when tunnel creation fails after upload.
- Cleanup is attempted again when the keepalive monitor observes tunnel death.
- Cleanup is attempted on clean ADscan shutdown for persisted Ligolo pivots.

The implementation only supports the current WinRM-backed Ligolo workflow. When
no reusable cleartext credential is available, ADscan records that operator
action is required and surfaces the exact remote path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any, Callable

from adscan_internal import print_info, print_info_debug, print_warning, telemetry
from adscan_internal.rich_output import confirm_operation, mark_sensitive
from adscan_internal.services.ligolo_service import LigoloProxyService


@dataclass(frozen=True, slots=True)
class LigoloArtifactCleanupResult:
    """Outcome of one remote Ligolo artifact cleanup attempt."""

    tunnel_id: str | None
    domain: str
    pivot_host: str
    remote_agent_path: str
    cleanup_attempted: bool
    cleanup_succeeded: bool
    credential_available: bool
    process_stop_attempted: bool
    process_stopped: bool
    file_existed_before: bool
    file_deleted: bool
    reason: str
    message: str


def _utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO format."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def confirm_ligolo_artifact_deployment(
    *,
    pivot_host: str,
    remote_agent_path: str,
    default: bool,
) -> bool:
    """Confirm remote agent staging with one rich deployment prompt."""

    context = {
        "Pivot Host": mark_sensitive(pivot_host, "hostname"),
        "Staged Agent": mark_sensitive(remote_agent_path, "path"),
        "Cleanup": "On failure, tunnel drop, or clean ADscan exit",
    }
    description = (
        "ADscan will stage a temporary Ligolo agent on the pivot host so the tunnel can be established. "
        "The binary must remain present while the tunnel is active. Abrupt operator shutdowns can leave the file behind "
        "on the target host, so exit ADscan cleanly whenever possible."
    )
    return confirm_operation(
        "Ligolo Pivot Deployment",
        description,
        context=context,
        default=default,
        icon="🧭",
        show_panel=True,
    )


def _build_windows_ligolo_cleanup_script(
    *,
    remote_agent_path: str,
    remote_agent_pid: int | None,
) -> str:
    """Return one PowerShell script that stops and deletes a staged Ligolo agent."""

    escaped_path = str(remote_agent_path).replace("'", "''")
    pid_literal = str(int(remote_agent_pid)) if isinstance(remote_agent_pid, int) and remote_agent_pid > 0 else "$null"
    return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$agentPath = '{escaped_path}'
$agentPid = {pid_literal}
$result = [ordered]@{{
    path = $agentPath
    pid = $agentPid
    file_existed_before = $false
    process_stop_attempted = $false
    process_stopped = $false
    file_deleted = $false
    cleanup_error = $null
}}
$result.file_existed_before = Test-Path -LiteralPath $agentPath

if ($agentPid) {{
    try {{
        $proc = Get-Process -Id $agentPid -ErrorAction Stop
        if ($proc) {{
            $result.process_stop_attempted = $true
            Stop-Process -Id $agentPid -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            $result.process_stopped = -not (Get-Process -Id $agentPid -ErrorAction SilentlyContinue)
        }}
    }} catch {{}}
}}

if (-not $result.process_stop_attempted) {{
    try {{
        $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {{ $_.ExecutablePath -eq $agentPath }})
        if ($procs.Count -gt 0) {{
            $result.process_stop_attempted = $true
            foreach ($proc in $procs) {{
                Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
            }}
            Start-Sleep -Seconds 2
            $stillRunning = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {{ $_.ExecutablePath -eq $agentPath }})
            $result.process_stopped = ($stillRunning.Count -eq 0)
        }}
    }} catch {{}}
}}

try {{
    if (Test-Path -LiteralPath $agentPath) {{
        Remove-Item -LiteralPath $agentPath -Force -ErrorAction Stop
    }}
    $result.file_deleted = -not (Test-Path -LiteralPath $agentPath)
}} catch {{
    $result.cleanup_error = $_.Exception.Message
    $result.file_deleted = -not (Test-Path -LiteralPath $agentPath)
}}

[PSCustomObject]$result | ConvertTo-Json -Depth 4 -Compress
"""


def cleanup_remote_ligolo_artifact(
    *,
    domain: str,
    pivot_host: str,
    username: str,
    password: str,
    remote_agent_path: str,
    remote_agent_pid: int | None,
    execute_remote_script: Callable[..., str],
    tunnel_id: str | None = None,
    reason: str,
) -> LigoloArtifactCleanupResult:
    """Best-effort removal of one remote Ligolo agent artifact via WinRM."""

    if not remote_agent_path:
        return LigoloArtifactCleanupResult(
            tunnel_id=tunnel_id,
            domain=domain,
            pivot_host=pivot_host,
            remote_agent_path="",
            cleanup_attempted=False,
            cleanup_succeeded=False,
            credential_available=bool(password),
            process_stop_attempted=False,
            process_stopped=False,
            file_existed_before=False,
            file_deleted=False,
            reason=reason,
            message="No remote Ligolo agent path was recorded.",
        )

    if not password:
        return LigoloArtifactCleanupResult(
            tunnel_id=tunnel_id,
            domain=domain,
            pivot_host=pivot_host,
            remote_agent_path=remote_agent_path,
            cleanup_attempted=False,
            cleanup_succeeded=False,
            credential_available=False,
            process_stop_attempted=False,
            process_stopped=False,
            file_existed_before=False,
            file_deleted=False,
            reason=reason,
            message="No reusable cleartext credential is available for remote cleanup.",
        )

    cleanup_script = _build_windows_ligolo_cleanup_script(
        remote_agent_path=remote_agent_path,
        remote_agent_pid=remote_agent_pid,
    )
    try:
        stdout_text = execute_remote_script(
            domain=domain,
            host=pivot_host,
            username=username,
            password=password,
            script=cleanup_script,
            operation_name="ligolo_agent_cleanup",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return LigoloArtifactCleanupResult(
            tunnel_id=tunnel_id,
            domain=domain,
            pivot_host=pivot_host,
            remote_agent_path=remote_agent_path,
            cleanup_attempted=True,
            cleanup_succeeded=False,
            credential_available=True,
            process_stop_attempted=False,
            process_stopped=False,
            file_existed_before=False,
            file_deleted=False,
            reason=reason,
            message=f"Remote cleanup failed: {exc}",
        )

    payload: dict[str, Any] = {}
    try:
        parsed = json.loads(str(stdout_text or "").strip() or "{}")
        if isinstance(parsed, dict):
            payload = parsed
    except json.JSONDecodeError:
        print_info_debug(f"[ligolo-cleanup] unexpected cleanup payload: {stdout_text!r}")

    file_existed_before = bool(payload.get("file_existed_before"))
    file_deleted = bool(payload.get("file_deleted"))
    process_stop_attempted = bool(payload.get("process_stop_attempted"))
    process_stopped = bool(payload.get("process_stopped"))
    cleanup_error = str(payload.get("cleanup_error") or "").strip()
    cleanup_succeeded = file_deleted or not file_existed_before
    message = cleanup_error or (
        "Remote Ligolo artifact deleted."
        if cleanup_succeeded
        else "Remote Ligolo artifact could not be confirmed as deleted."
    )

    return LigoloArtifactCleanupResult(
        tunnel_id=tunnel_id,
        domain=domain,
        pivot_host=pivot_host,
        remote_agent_path=remote_agent_path,
        cleanup_attempted=True,
        cleanup_succeeded=cleanup_succeeded,
        credential_available=True,
        process_stop_attempted=process_stop_attempted,
        process_stopped=process_stopped,
        file_existed_before=file_existed_before,
        file_deleted=file_deleted,
        reason=reason,
        message=message,
    )


def _resolve_reusable_password(shell: Any, *, domain: str, username: str) -> str | None:
    """Return one reusable cleartext password from workspace credential state."""

    domains_data = getattr(shell, "domains_data", {})
    domain_data = domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
    credentials = domain_data.get("credentials", {}) if isinstance(domain_data, dict) else {}
    if not isinstance(credentials, dict):
        return None
    secret = str(credentials.get(username) or "").strip()
    if not secret:
        return None
    if getattr(shell, "is_hash", lambda _: False)(secret):
        return None
    return secret


def _persist_cleanup_result(
    *,
    service: LigoloProxyService,
    tunnel_id: str | None,
    result: LigoloArtifactCleanupResult,
) -> None:
    """Persist cleanup metadata back to the workspace tunnel record."""

    if not tunnel_id:
        return
    status = "deleted" if result.cleanup_succeeded else "operator_action_required"
    service.update_tunnel_record(
        tunnel_id=tunnel_id,
        updates={
            "remote_artifact_cleanup_at": _utc_now_iso(),
            "remote_artifact_cleanup_reason": result.reason,
            "remote_artifact_cleanup_status": status,
            "remote_artifact_cleanup_message": result.message,
            "remote_artifact_deleted": result.file_deleted,
        },
    )


def cleanup_workspace_ligolo_artifacts(
    shell: Any,
    *,
    reason: str,
) -> list[LigoloArtifactCleanupResult]:
    """Best-effort cleanup of persisted Ligolo agent artifacts for one workspace."""

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if not workspace_dir:
        return []

    service = LigoloProxyService(
        workspace_dir=workspace_dir,
        current_domain=getattr(shell, "current_domain", None),
    )
    candidates = [
        dict(record)
        for record in service.load_tunnels_state()
        if str(record.get("pivot_tool") or "").strip().lower() == "ligolo"
        and str(record.get("source_service") or "").strip().lower() == "winrm"
        and str(record.get("remote_agent_path") or "").strip()
        and str(record.get("remote_artifact_cleanup_status") or "").strip().lower() != "deleted"
    ]
    if not candidates:
        return []

    print_info("ADscan is cleaning up staged Ligolo agent artifacts. Please wait...")
    results: list[LigoloArtifactCleanupResult] = []
    for record in candidates:
        tunnel_id = str(record.get("tunnel_id") or "").strip() or None
        domain = str(record.get("domain") or "").strip()
        pivot_host = str(record.get("pivot_host") or "").strip()
        username = str(record.get("pivot_username") or "").strip()
        remote_agent_path = str(record.get("remote_agent_path") or "").strip()
        remote_agent_pid = record.get("remote_agent_pid")
        password = _resolve_reusable_password(shell, domain=domain, username=username)

        if tunnel_id:
            service.update_tunnel_record(
                tunnel_id=tunnel_id,
                updates={
                    "shutdown_requested": True,
                    "shutdown_requested_at": _utc_now_iso(),
                    "shutdown_reason": reason,
                },
            )

        if tunnel_id and str(record.get("status") or "").strip().lower() in {"running", "connected", "disconnected"}:
            try:
                service.stop_tunnel(tunnel_id=tunnel_id)
            except Exception as exc:  # noqa: BLE001
                print_info_debug(f"[ligolo-cleanup] stop_tunnel failed for {tunnel_id}: {exc}")

        from adscan_internal.cli.winrm import _execute_powershell_via_psrp  # noqa: PLC0415

        result = cleanup_remote_ligolo_artifact(
            domain=domain,
            pivot_host=pivot_host,
            username=username,
            password=str(password or ""),
            remote_agent_path=remote_agent_path,
            remote_agent_pid=remote_agent_pid if isinstance(remote_agent_pid, int) else None,
            execute_remote_script=_execute_powershell_via_psrp,
            tunnel_id=tunnel_id,
            reason=reason,
        )
        _persist_cleanup_result(service=service, tunnel_id=tunnel_id, result=result)
        results.append(result)

        if result.cleanup_succeeded:
            print_info(
                f"Removed Ligolo agent artifact from {mark_sensitive(pivot_host, 'hostname')}: "
                f"{mark_sensitive(remote_agent_path, 'path')}"
            )
        elif not result.credential_available:
            print_warning(
                f"ADscan could not clean the Ligolo agent artifact on "
                f"{mark_sensitive(pivot_host, 'hostname')} because no reusable cleartext credential is stored.",
                items=[f"Verify manually: {mark_sensitive(remote_agent_path, 'path')}"],
                panel=True,
            )
        else:
            print_warning(
                f"ADscan could not confirm Ligolo artifact cleanup on {mark_sensitive(pivot_host, 'hostname')}.",
                items=[
                    f"Path: {mark_sensitive(remote_agent_path, 'path')}",
                    result.message,
                ],
                panel=True,
            )
    return results


__all__ = [
    "confirm_ligolo_artifact_deployment",
    "LigoloArtifactCleanupResult",
    "cleanup_remote_ligolo_artifact",
    "cleanup_workspace_ligolo_artifacts",
]
