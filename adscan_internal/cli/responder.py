"""Responder CLI orchestration helpers.

This module extracts Responder management logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

import os
import signal
import sqlite3
import threading
import time
from typing import Any, Protocol

from adscan_internal import telemetry
from adscan_internal.constants import TOOLS_INSTALL_DIR
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_instruction,
    print_success,
    print_warning,
    print_exception,
)
from adscan_internal.cli.creds import save_ntlm_hash


class ResponderShell(Protocol):
    """Protocol for Responder management methods on the legacy shell."""

    interface: str | None
    responder_python: str | None
    responder_process: Any
    domains_data: dict[str, dict[str, Any]]
    domains_dir: str
    cracking_dir: str
    current_workspace_dir: str | None

    def spawn_command(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        shell: bool = False,
        stdout: Any = None,
        stderr: Any = None,
        preexec_fn: Any = None,
    ) -> Any:
        """Spawn a command in the background."""
        ...

    def ask_for_cracking(
        self,
        hash_type: str,
        domain: str,
        hashes_file: str,
        *,
        confirm: bool = True,
    ) -> None:
        """Ask user if they want to crack hashes."""
        ...


def extract_username_and_netbios(user: str) -> tuple[str, str | None]:
    """Extract the username and the NetBIOS domain name.

    Args:
        user: Username string, potentially with NetBIOS domain (e.g., "DOMAIN\\user")

    Returns:
        Tuple of (username, netbios_domain). netbios_domain is None if not present.
    """
    if "\\" in user:
        netbios_domain, username = user.split("\\", 1)
        return username, netbios_domain
    return user, None


def find_domain_by_netbios(shell: ResponderShell, netbios: str | None) -> str | None:
    """Search for the full domain corresponding to a NetBIOS domain name.

    Args:
        shell: The shell instance with domains_data
        netbios: NetBIOS domain name to search for

    Returns:
        Full domain name if found, None otherwise
    """
    if not netbios:
        return None

    for domain, data in shell.domains_data.items():
        if "netbios" in data and data["netbios"] == netbios:
            return domain
    return None


def execute_responder(
    shell: ResponderShell, command: list[str], env: dict[str, str]
) -> None:
    """Execute Responder in the background.

    Args:
        shell: The shell instance with spawn_command method
        command: Command to execute as list
        env: Environment variables dictionary
    """
    print_info_debug(
        f"[DEBUG] execute_responder: Received command: {' '.join(command)}"
    )
    print_info_debug(
        f"[DEBUG] execute_responder: Received environment with keys (sample): {list(env.keys())[:10]}..."
    )
    try:
        # Launch responder in background with inherited stdio
        shell.responder_process = shell.spawn_command(
            command,
            env=env,
            shell=False,
            stdout=None,
            stderr=None,
            preexec_fn=os.setsid,
        )
        print_info_debug(
            f"[DEBUG] execute_responder: self.responder_process object: {shell.responder_process}"
        )
        if shell.responder_process and hasattr(shell.responder_process, "pid"):
            print_info_debug(
                f"[DEBUG] execute_responder: Responder process PID: {shell.responder_process.pid}"
            )
        else:
            print_info_debug(
                "[DEBUG] execute_responder: Responder process object is None or does not have a PID."
            )

    except Exception as e:
        telemetry.capture_exception(e)
        print_info_debug(
            f"[DEBUG] execute_responder: Exception during responder launch: {str(e)}"
        )
        print_error("Error executing Responder.")
        print_exception(show_locals=False, exception=e)


def monitor_responder_db(shell: ResponderShell, _args: str) -> None:
    """Monitor Responder database for new hashes.

    This function runs in a loop, checking the Responder database for new
    NTLMv1 and NTLMv2 hashes. When new hashes are found, they are saved
    to the domain's cracking directory and the user is prompted to crack them.

    Args:
        shell: The shell instance with domain data and methods
        _args: Unused argument (for compatibility with threading)
    """
    db_path = os.path.join(TOOLS_INSTALL_DIR, "responder", "Responder.db")
    processed_users = set()  # Store already processed users

    while True:
        try:
            if not os.path.exists(db_path):
                time.sleep(1)
                continue

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Search for NTLMv1 and NTLMv2 hashes
            for hash_ver in ["v1", "v2"]:
                query = f"SELECT user, fullhash FROM Responder WHERE type LIKE '%{hash_ver}%'"
                cursor.execute(query)
                results = cursor.fetchall()

                for raw_user, hash_value in results:
                    clean_user, netbios_domain = extract_username_and_netbios(raw_user)

                    # Find the full domain based on NetBIOS
                    domain = find_domain_by_netbios(shell, netbios_domain)

                    if not domain:
                        print_warning(f"No domain found for NetBIOS: {netbios_domain}")
                        continue

                    # If the user has not been processed
                    if clean_user not in processed_users:
                        processed_users.add(clean_user)  # Add immediately to processed
                        # Try to save the hash
                        if save_ntlm_hash(
                            shell, domain, hash_ver, clean_user, hash_value
                        ):
                            print_success(f"New NTLM{hash_ver} hash captured:")
                            print_info(f"User: {clean_user}", spacing="none")
                            print_info(
                                f"NetBIOS Domain: {netbios_domain}",
                                spacing="none",
                            )
                            marked_domain = mark_sensitive(domain, "domain")
                            print_info(f"Full Domain: {marked_domain}", spacing="none")
                            print_info(f"Hash: {hash_value}", spacing="none")
                            hash_file = os.path.join(
                                shell.domains_dir,
                                domain,
                                shell.cracking_dir,
                                f"{clean_user}_hashes.NTLM{hash_ver}",
                            )
                            # Ask if user wants to crack only if hash is new
                            shell.ask_for_cracking(
                                f"{clean_user}.NTLM{hash_ver}", domain, hash_file
                            )

            conn.close()
            time.sleep(1)  # Wait before next check

        except Exception as e:
            telemetry.capture_exception(e)
            print_error("Error monitoring database.")
            print_exception(show_locals=False, exception=e)
            time.sleep(1)


def start_responder(shell: ResponderShell) -> None:
    """Start Responder to capture network hashes and begin monitoring the database.

    This function checks if the network interface is configured before starting Responder.
    If the interface is configured, it creates two threads: one to execute Responder and another
    to monitor its database for new hashes.

    Requires that the shell instance variable `interface` is configured with the appropriate
    network interface before execution. Use 'stop_responder' to stop the processes started.
    """
    if not shell.interface:
        print_error("The network interface must be configured before running Responder")
        return

    env = os.environ.copy()
    # Use Python from isolated venv if available, fallback to system python
    responder_python = shell.responder_python or "python"
    command = [
        responder_python,
        os.path.join(TOOLS_INSTALL_DIR, "responder", "Responder.py"),
        "-I",
        shell.interface,
    ]

    # Debug logs
    print_info_debug(f"[DEBUG] start_responder: Prepared command: {' '.join(command)}")
    print_info_debug(
        f"[DEBUG] start_responder: Passing environment with keys (sample): {list(env.keys())[:10]}..."
    )

    # Original user-facing message
    print_info("Starting Responder to capture hashes")

    # Start Responder (execute_responder is now non-blocking as Popen is used without wait)
    execute_responder(shell, command, env)

    # Create thread to monitor the database
    monitor_thread = threading.Thread(target=monitor_responder_db, args=(shell, ""))
    monitor_thread.start()

    print_instruction(
        "Responder and monitoring started in the background. Use 'stop_responder' to stop them."
    )


def clear_responder_db(shell: ResponderShell) -> None:
    """Clear the Responder database by deleting all records from the Responder table.

    Args:
        shell: The shell instance (unused but kept for consistency)
    """
    db_path = os.path.join(TOOLS_INSTALL_DIR, "responder", "Responder.db")
    try:
        if not os.path.exists(db_path):
            print_error("Responder database not found")
            return

        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Delete all records from the Responder table
        cursor.execute("DELETE FROM Responder")
        conn.commit()

        # Close the connection
        conn.close()

        print_success("Responder database cleared successfully")

    except sqlite3.Error as e:
        telemetry.capture_exception(e)
        print_error("SQLite error while clearing the database.")
        print_exception(show_locals=False, exception=e)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error clearing the database.")
        print_exception(show_locals=False, exception=e)


def stop_responder(shell: ResponderShell) -> None:
    """Stop the running Responder process, if it exists.

    Args:
        shell: The shell instance with responder_process attribute
    """
    try:
        if hasattr(shell, "responder_process") and shell.responder_process:
            os.killpg(os.getpgid(shell.responder_process.pid), signal.SIGTERM)
            print_success("Responder stopped.")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error stopping Responder.")
        print_exception(show_locals=False, exception=e)
