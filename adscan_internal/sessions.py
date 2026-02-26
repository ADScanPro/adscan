"""Session management helpers for ADscan.

This module defines a lightweight, extensible abstraction for remote sessions
obtained during an engagement (for example, reverse shells or interactive
execution channels on target hosts).

The initial implementation focuses on:

- A `RemoteSession` data model to represent an interactive channel.
- A `SessionManager` that tracks all sessions within a PentestShell instance.
- A minimal TCP reverse-shell listener that accepts connections and registers
  them as sessions.

Higher-level integration (command helpers that use specific tools like netexec,
WinRM, SSH, etc.) can build on top of this module without embedding tool-
specific logic here.
"""

from __future__ import annotations

import logging
import os
import select
import socket
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console

from . import telemetry
from .rich_output import (
    print_error,
    print_error_debug,
    print_info,
    print_info_debug,
    print_success,
    print_warning,
)

logger = logging.getLogger("adscan.sessions")

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - non-POSIX platforms
    termios = None  # type: ignore[assignment]
    tty = None  # type: ignore[assignment]


class SessionType(str, Enum):
    """Enumeration of supported session types."""

    REVERSE_TCP = "reverse_tcp"
    AGENT = "agent"


@dataclass
class RemoteSession:
    """Represents an interactive remote session.

    Attributes:
        id: Numeric identifier unique within a SessionManager.
        type: Session type identifier (for example, "reverse_tcp").
        peer_address: Tuple of (ip, port) for the remote endpoint.
        created_at: UTC datetime when the session was created.
        description: Optional human-friendly description.
        socket: Underlying TCP socket for the session (if applicable).
        is_active: True while the session is considered usable.
    """

    id: int
    type: SessionType
    peer_address: Tuple[str, int]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""
    socket: Optional[socket.socket] = None
    is_active: bool = True
    alias: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def close(self) -> None:
        """Close the underlying transport and mark the session inactive."""
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                # Socket might already be closed or half-closed
                pass
            try:
                self.socket.close()
            except OSError:
                pass
        self.is_active = False


class SessionManager:
    """Manage remote sessions and TCP listeners for a PentestShell instance.

    This manager is intentionally self-contained and does not depend on
    prompt-toolkit or shell internals. PentestShell can delegate user-facing
    commands (list, use, kill, interact) to this manager.
    """

    def __init__(self) -> None:
        self._sessions: Dict[int, RemoteSession] = {}
        self._next_id: int = 1
        self._current_session_id: Optional[int] = None
        self._listener_thread: Optional[threading.Thread] = None
        self._listener_socket: Optional[socket.socket] = None
        self._listener_stop_event = threading.Event()
        self._listener_bind: Optional[Tuple[str, int]] = None

    # ------------------------------------------------------------------ #
    # Session operations
    # ------------------------------------------------------------------ #
    def list_sessions(self) -> List[RemoteSession]:
        """Return a snapshot list of all known sessions."""
        return list(self._sessions.values())

    def get_session(self, session_id: int) -> Optional[RemoteSession]:
        """Return a session by id, or None if it does not exist."""
        return self._sessions.get(session_id)

    def add_session_from_socket(
        self,
        session_type: SessionType,
        sock: socket.socket,
        addr: Tuple[str, int],
        description: str = "",
    ) -> RemoteSession:
        """Register a new session backed by an established socket."""
        session_id = self._next_id
        self._next_id += 1
        session = RemoteSession(
            id=session_id,
            type=session_type,
            peer_address=addr,
            description=description,
            socket=sock,
        )
        self._sessions[session_id] = session
        # If this is the first session, make it current implicitly.
        if self._current_session_id is None:
            self._current_session_id = session_id
        print_success(
            f"New {session.type.value} session #{session.id} "
            f"from {session.peer_address[0]}:{session.peer_address[1]}"
        )
        return session

    def connect_tcp(
        self, host: str, port: int, description: str | None = None
    ) -> Optional[RemoteSession]:
        """Establish an outbound TCP connection and register it as a session.

        This is complementary to the reverse-shell listener and can be used for
        bind shells or other TCP services that expose an interactive console.

        Args:
            host: Remote host/IP to connect to.
            port: Remote TCP port.
            description: Optional human-friendly description.

        Returns:
            A ``RemoteSession`` instance if the connection succeeds, otherwise
            ``None``.
        """
        try:
            sock = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_error(f"Failed to connect to {host}:{port}: {exc}")
            return None

        try:
            peer_addr = sock.getpeername()
        except OSError:
            peer_addr = (host, port)

        session_description = (
            description
            if description
            else f"TCP connection to {peer_addr[0]}:{peer_addr[1]}"
        )
        return self.add_session_from_socket(
            SessionType.REVERSE_TCP, sock, peer_addr, description=session_description
        )

    def set_current_session(self, session_id: int) -> bool:
        """Select the current active session by id.

        Returns:
            True if the session exists and becomes current, False otherwise.
        """
        if session_id in self._sessions:
            self._current_session_id = session_id
            session = self._sessions[session_id]
            print_info(
                f"Switched to session #{session.id} "
                f"({session.type.value} {session.peer_address[0]}:{session.peer_address[1]})"
            )
            return True
        print_warning(f"Session #{session_id} not found.")
        return False

    def get_current_session(self) -> Optional[RemoteSession]:
        """Return the currently selected session, or None."""
        if self._current_session_id is None:
            return None
        return self._sessions.get(self._current_session_id)

    def kill_session(self, session_id: int) -> bool:
        """Terminate and remove a session by id."""
        session = self._sessions.pop(session_id, None)
        if not session:
            print_warning(f"Session #{session_id} not found.")
            return False
        try:
            session.close()
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            print_error_debug(f"Error closing session #{session_id}: {exc}")
        print_success(
            f"Session #{session_id} "
            f"({session.peer_address[0]}:{session.peer_address[1]}) terminated."
        )
        if self._current_session_id == session_id:
            self._current_session_id = None
        return True

    def rename_session(self, session_id: int, alias: str) -> bool:
        """Assign or update a human-friendly alias for a session."""
        session = self._sessions.get(session_id)
        if not session:
            print_warning(f"Session #{session_id} not found.")
            return False
        session.alias = alias.strip()
        if session.alias:
            print_success(f"Session #{session_id} alias set to '{session.alias}'.")
        else:
            print_success(f"Alias cleared for session #{session_id}.")
        return True

    # ------------------------------------------------------------------ #
    # Reverse TCP listener
    # ------------------------------------------------------------------ #
    def is_listener_running(self) -> bool:
        """Return True if a reverse-shell listener is active."""
        return self._listener_thread is not None and self._listener_thread.is_alive()

    def get_listener_bind(self) -> Optional[Tuple[str, int]]:
        """Return current listener (host, port) if running."""
        return self._listener_bind if self.is_listener_running() else None

    def start_listener(self, host: str, port: int) -> bool:
        """Start a background TCP listener for reverse shells.

        This listener accepts incoming TCP connections and registers each one
        as a new `RemoteSession` with type `REVERSE_TCP`.
        """
        if self.is_listener_running():
            active_host, active_port = self._listener_bind or ("0.0.0.0", 0)
            print_warning(
                f"Listener already running on {active_host}:{active_port}. Stop it first."
            )
            return False

        self._listener_stop_event.clear()

        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow quick reuse when restarting during testing.
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind((host, port))
            listen_sock.listen(5)
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_error(f"Failed to start listener on {host}:{port}: {exc}")
            return False

        self._listener_socket = listen_sock
        self._listener_bind = (host, port)

        def _listener_loop() -> None:
            print_info_debug(
                f"[sessions] Listener loop started on {host}:{port} (reverse_tcp)."
            )
            while not self._listener_stop_event.is_set():
                try:
                    listen_sock.settimeout(1.0)
                    client_sock, addr = listen_sock.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    # Socket closed or other fatal error – exit loop.
                    telemetry.capture_exception(exc)
                    print_error_debug(
                        f"[sessions] Listener accept failed: {type(exc).__name__}: {exc}"
                    )
                    break

                try:
                    self.add_session_from_socket(
                        SessionType.REVERSE_TCP,
                        client_sock,
                        addr,
                        description="Reverse TCP session",
                    )
                except Exception as exc:  # pragma: no cover - defensive
                    telemetry.capture_exception(exc)
                    print_error_debug(
                        f"[sessions] Error registering new session from "
                        f"{addr[0]}:{addr[1]}: {exc}"
                    )
                    try:
                        client_sock.close()
                    except OSError:
                        pass

            print_info_debug("[sessions] Listener loop terminating.")
            try:
                listen_sock.close()
            except OSError:
                pass

        thread = threading.Thread(target=_listener_loop, daemon=True)
        thread.start()
        self._listener_thread = thread
        print_success(f"Reverse-shell listener started on {host}:{port}.")
        return True

    def stop_listener(self) -> bool:
        """Stop the reverse-shell listener if it is running."""
        if not self.is_listener_running():
            print_warning("No active listener to stop.")
            return False

        self._listener_stop_event.set()
        if self._listener_socket:
            try:
                self._listener_socket.close()
            except OSError:
                pass
        if self._listener_thread:
            self._listener_thread.join(timeout=2.0)
        bind = self._listener_bind
        self._listener_thread = None
        self._listener_socket = None
        self._listener_bind = None
        if bind:
            print_success(f"Listener on {bind[0]}:{bind[1]} stopped.")
        else:
            print_success("Listener stopped.")
        return True

    # ------------------------------------------------------------------ #
    # Interactive session handling
    # ------------------------------------------------------------------ #
    def interact(self, session_id: int, console: Console) -> None:
        """Enter an interactive shell with the given session.

        This attaches the local terminal to the remote session until the user
        detaches (Ctrl-]) or the remote side closes the connection.
        """
        session = self.get_session(session_id)
        if session is None or session.socket is None or not session.is_active:
            print_error(f"Session #{session_id} is not active or has no socket.")
            return

        if termios is None or tty is None:
            print_error(
                "Interactive session mode is only supported on POSIX terminals "
                "(termios/tty modules are required)."
            )
            return

        sock = session.socket
        sock.setblocking(False)

        console.print(
            f"[bold cyan]Interactive session #[/bold cyan]{session.id} "
            f"({session.peer_address[0]}:{session.peer_address[1]}). "
            "Press [bold]Ctrl-][/bold] to detach.\n"
        )

        fd = sys.stdin.fileno()
        try:
            old_settings = termios.tcgetattr(fd)
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            print_error("Failed to configure terminal for interactive mode.")
            return

        escape_char = b"\x1d"  # Ctrl-]

        try:
            tty.setraw(fd)

            while True:
                try:
                    rlist, _, _ = select.select([fd, sock], [], [])
                except (OSError, ValueError) as exc:
                    telemetry.capture_exception(exc)
                    print_error_debug(
                        f"[sessions] select() failed in interactive mode: {exc}"
                    )
                    break

                if sock in rlist:
                    try:
                        data = sock.recv(4096)
                    except OSError as exc:
                        telemetry.capture_exception(exc)
                        print_error_debug(
                            f"[sessions] recv() failed in interactive mode: {exc}"
                        )
                        break

                    if not data:
                        console.print(
                            "\n[bold yellow]Remote host closed the session.[/bold yellow]"
                        )
                        session.is_active = False
                        break

                    try:
                        text = data.decode(errors="ignore")
                    except Exception:
                        text = repr(data)
                    # Use console.print with end="" to avoid extra newlines.
                    console.print(text, end="")

                if fd in rlist:
                    try:
                        chunk = os.read(fd, 1024)
                    except OSError as exc:
                        telemetry.capture_exception(exc)
                        print_error_debug(
                            f"[sessions] os.read() failed in interactive mode: {exc}"
                        )
                        break

                    if not chunk:
                        continue

                    if escape_char in chunk:
                        console.print(
                            "\n[bold cyan]Detaching from interactive session.[/bold cyan]\n"
                        )
                        break

                    try:
                        sock.sendall(chunk)
                    except OSError as exc:
                        telemetry.capture_exception(exc)
                        console.print(
                            "\n[bold red]Failed to send data to remote host.[/bold red]\n"
                        )
                        break

        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)  # type: ignore[arg-type]
            except Exception as exc:  # pragma: no cover - best effort
                telemetry.capture_exception(exc)
                print_error_debug(
                    f"[sessions] Failed to restore terminal settings: {exc}"
                )
