"""Flags CLI orchestration helpers.

This module extracts flags-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.

Note: This module handles HTB/THM flag extraction operations.
"""

from __future__ import annotations

from typing import Any
import os
import re
import subprocess

import rich.box
from rich.prompt import Confirm
from rich.table import Table

from adscan_internal import (
    print_error,
    print_info,
    print_success,
    print_warning,
    print_warning_verbose,
    telemetry,
)
from adscan_internal.cli.smb import run_get_flags
from adscan_internal.integrations.netexec.exec import run_netexec_remote_command
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.rich_output import mark_sensitive


def ask_for_flags(shell: Any, domain: str, username: str, password: str) -> None:
    """Ask user if they want to obtain flags from domain.

    Args:
        shell: The ADscan shell instance.
        domain: Domain name.
        username: Username for authentication.
        password: Password for authentication.
    """
    if shell.auto:
        get_flags(shell, domain, username, password)
    else:
        marked_domain = mark_sensitive(domain, "domain")
        respuesta = Confirm.ask(
            f"Do you want to obtain flags from domain {marked_domain}?"
        )
        if respuesta:
            get_flags(shell, domain, username, password)


def get_flags(shell: Any, domain: str, username: str, password: str) -> None:
    """Obtain flags from the specified domain.

    Args:
        shell: The ADscan shell instance.
        domain: Domain name.
        username: Username for authentication.
        password: Password for authentication.
    """
    return run_get_flags(shell, domain=domain, username=username, password=password)


def do_get_flags(shell: Any, args: str) -> None:
    """Obtains flags from the specified domain.

    Usage: get_flags <domain> <username> <password>

    Requires that the domain's PDC is defined in the domains list and that a username and password
    have been specified for authentication.

    If an error occurs while executing the command, an error message is displayed and it continues with the next domain.

    Args:
        shell: The ADscan shell instance.
        args: Command arguments as string (domain username password).
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: get_flags <domain> <username> <password>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    get_flags(shell, domain, username, password)


def _parse_flags_from_output(stdout: str) -> list[tuple[str, str, str]]:
    """Parse flags from NetExec output.

    Args:
        stdout: The stdout output from NetExec command.

    Returns:
        List of tuples (kind, path, flag) where kind is "user", "root", "system", or "unknown".
    """
    stdout = stdout or ""
    clean_stdout = strip_ansi_codes(stdout)

    lines = clean_stdout.splitlines()

    # Parse pattern: "...>type \"C:\\Users\\...\\(user|root|system).txt\"" then next line is the flag
    last_path = None
    results = []  # list of (kind, path, flag)
    for line in lines:
        if '>type "' in line:
            try:
                start = line.index('>type "') + len('>type "')
                end = line.index('"', start)
                last_path = line[start:end]
            except Exception:
                last_path = None
            continue
        if last_path:
            m = re.search(r"\b[a-f0-9]{32}\b", line.lower())
            if m:
                kind = (
                    "user"
                    if last_path.lower().endswith("user.txt")
                    else (
                        "root"
                        if last_path.lower().endswith("root.txt")
                        else (
                            "system"
                            if last_path.lower().endswith("system.txt")
                            else "unknown"
                        )
                    )
                )
                results.append((kind, last_path, m.group(0)))
                last_path = None

    return results


def _save_flags_to_files(
    shell: Any, results: list[tuple[str, str, str]], _domain: str
) -> None:
    """Save flags to files in workspace flags directory.

    Args:
        shell: The ADscan shell instance.
        results: List of tuples (kind, path, flag).
        _domain: Domain name (unused, kept for API compatibility).
    """
    if not shell.current_workspace_dir:
        return

    flags_dir = os.path.join(shell.current_workspace_dir, "flags")
    os.makedirs(flags_dir, exist_ok=True)

    user_flag = None
    root_flag = None
    system_flag = None
    for kind, path, flag in results:
        if kind == "user" and user_flag is None:
            user_flag = flag
        elif kind == "root" and root_flag is None:
            root_flag = flag
        elif kind == "system" and system_flag is None:
            system_flag = flag

    if user_flag:
        user_flag_path = os.path.join(flags_dir, "user.txt")
        try:
            with open(user_flag_path, "w", encoding="utf-8") as f:
                f.write(user_flag)
            print_info(f"User flag saved to: {user_flag_path}")
        except Exception as e:
            telemetry.capture_exception(e)
            print_warning_verbose(f"Failed to save user flag: {e}")

    if root_flag:
        root_flag_path = os.path.join(flags_dir, "root.txt")
        try:
            with open(root_flag_path, "w", encoding="utf-8") as f:
                f.write(root_flag)
            print_info(f"Root flag saved to: {root_flag_path}")
        except Exception as e:
            telemetry.capture_exception(e)
            print_warning_verbose(f"Failed to save root flag: {e}")

    if system_flag:
        system_flag_path = os.path.join(flags_dir, "system.txt")
        try:
            with open(system_flag_path, "w", encoding="utf-8") as f:
                f.write(system_flag)
            print_info(f"System flag saved to: {system_flag_path}")
        except Exception as e:
            telemetry.capture_exception(e)
            print_warning_verbose(f"Failed to save system flag: {e}")

        # Compatibility: some flows validate presence of root.txt as the "privileged" flag.
        # If only system.txt exists, also write root.txt with the same content.
        if not root_flag:
            root_flag_path = os.path.join(flags_dir, "root.txt")
            try:
                with open(root_flag_path, "w", encoding="utf-8") as f:
                    f.write(system_flag)
                print_info(f"Privileged flag saved to: {root_flag_path}")
            except Exception as e:
                telemetry.capture_exception(e)
                print_warning_verbose(
                    f"Failed to save privileged flag alias (root.txt): {e}"
                )


def execute_get_flags(
    shell: Any,
    *,
    domain: str,
    host: str,
    auth: str,
    remote_command: str,
) -> None:
    """Execute get_flags command with retry logic and execution method fallback.

    Notes:
        We intentionally do not force ``--exec-method`` here to allow NetExec to
        use its own internal fallback logic (atexec/wmiexec/etc).

    Args:
        shell: The ADscan shell instance.
        domain: Domain name for logging and error handling.
        host: Target host (PDC).
        auth: NetExec auth string.
        remote_command: Command to execute remotely.
    """
    max_attempts = 1

    try:
        # Use shared NetExec helper (lets NetExec handle internal exec-method fallback).
        exec_result = run_netexec_remote_command(
            shell,
            domain=domain,
            host=host,
            auth=auth,
            remote_command=remote_command,
            service="smb",
            timeout=300,
            attempts=max_attempts,
        )

        if not exec_result.output:
            print_error("Failed to execute flags command (no output).")
            return

        # Parse flags from output
        results = _parse_flags_from_output(exec_result.output)

        if results:
            # Success: flags found
            if exec_result.attempts > 1:
                print_success(
                    f"Flags found on attempt {exec_result.attempts}/{max_attempts}"
                )

            table = Table(title=f"Flags in domain {domain}", box=rich.box.ROUNDED)
            table.add_column("Type", style="cyan", no_wrap=True)
            table.add_column("Path", style="white")
            table.add_column("Flag", style="magenta")
            # order user then root then unknown
            order = {"user": 0, "root": 1, "system": 1}
            for kind, path, flag in sorted(results, key=lambda x: order.get(x[0], 99)):
                table.add_row(kind, path, flag)
            shell.console.print(table)

            # Save flags to files
            _save_flags_to_files(shell, results, domain)
            return  # Success, exit function

        print_warning(
            "No flags found. The flags may not exist or the command may need different parameters."
        )
    except subprocess.TimeoutExpired as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Timeout obtaining flags from domain {marked_domain}")
    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Error obtaining flags from domain {marked_domain}: {e}")
