"""Shared helpers for NetExec remote command execution (-x)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal import print_info_debug, print_warning
from adscan_internal.integrations.netexec.parsers import (
    NetexecExecStatus,
    parse_netexec_exec_status,
    parse_netexec_remote_command_output,
)
from adscan_internal.rich_output import mark_sensitive


@dataclass(frozen=True)
class NetexecRemoteExecResult:
    """Result of a NetExec remote command execution."""

    output: str
    command_output: str
    status: NetexecExecStatus
    method: str | None
    attempts: int


def run_netexec_remote_command(
    shell: Any,
    *,
    domain: str,
    host: str,
    auth: str,
    remote_command: str,
    service: str = "smb",
    exec_method: str | None = None,
    timeout: int = 300,
    attempts: int = 1,
    env: dict[str, str] | None = None,
) -> NetexecRemoteExecResult:
    """Execute a remote command via NetExec (-x), optionally forcing exec method.

    Notes:
        NetExec has its own internal execution method fallback logic, but it is
        typically disabled when callers force an explicit ``--exec-method``.
        Therefore, the default is to *not* force any exec method.
    """
    if not getattr(shell, "netexec_path", None):
        return NetexecRemoteExecResult(
            output="",
            command_output="",
            status=NetexecExecStatus(executed=False, method=None, not_found=[]),
            method=None,
            attempts=0,
        )

    service_clean = (service or "smb").strip().lower()
    current_method = exec_method
    max_attempts = max(1, attempts)
    output = ""
    status = NetexecExecStatus(executed=False, method=None, not_found=[])

    for attempt in range(1, max_attempts + 1):
        command = f'{shell.netexec_path} {service_clean} {host} {auth} -t 1 --timeout 60 -x "{remote_command}"'
        if service_clean == "smb":
            command = f"{command} --smb-timeout 30"
        if current_method:
            command = f"{command} --exec-method {current_method}"
        proc = shell._run_netexec(
            command,
            domain=domain,
            timeout=timeout,
            operation_kind=f"netexec_remote_exec:{service_clean}",
            service=service_clean,
            target_count=1,
            env=env,
        )
        output = ""
        if proc:
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        status = parse_netexec_exec_status(output)
        if status.executed:
            return NetexecRemoteExecResult(
                output=output,
                command_output=parse_netexec_remote_command_output(output),
                status=status,
                method=status.method or current_method,
                attempts=attempt,
            )

        if (
            service_clean == "smb"
            and current_method == "atexec"
            and (
                "SCHED_S_TASK_HAS_NOT_RUN" in output or "SCHED_E_MALFORMEDXML" in output
            )
        ):
            current_method = "wmiexec"
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[netexec] {marked_domain} remote exec failed with atexec; "
                "retrying with wmiexec."
            )
            continue

        if attempt < max_attempts:
            print_warning(
                f"Remote command execution returned no output on attempt "
                f"{attempt}/{max_attempts}. Retrying..."
            )
            continue

    return NetexecRemoteExecResult(
        output=output,
        command_output=parse_netexec_remote_command_output(output),
        status=status,
        method=status.method or current_method,
        attempts=max_attempts,
    )
