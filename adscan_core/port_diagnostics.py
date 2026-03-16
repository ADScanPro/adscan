"""Best-effort local TCP port diagnostics shared across ADscan components.

This module centralizes listener inspection and bind-availability checks so
feature-specific flows can share one consistent view of occupied local ports
without coupling their remediation logic.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import re
import socket
import subprocess
import time
from typing import Callable


@dataclass(frozen=True, slots=True)
class PortListenerInfo:
    """Describe one local TCP listener discovered through ``ss`` or ``lsof``."""

    port: int
    source: str
    bind_addr: str | None = None
    local_address: str | None = None
    process_name: str | None = None
    pid: int | None = None

    def render_summary(self) -> str:
        """Render one concise operator-facing summary."""

        local = str(self.local_address or self.bind_addr or self.port).strip() or str(self.port)
        process_bits: list[str] = []
        if self.process_name:
            process_bits.append(self.process_name)
        if isinstance(self.pid, int) and self.pid > 0:
            process_bits.append(f"pid {self.pid}")
        if process_bits:
            return f"{local} -> {' / '.join(process_bits)} ({self.source})"
        return f"{local} -> busy ({self.source})"


PortCommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def parse_host_port(bind_addr: str) -> tuple[str, int]:
    """Parse one ``host:port`` bind address."""

    raw_value = str(bind_addr or "").strip()
    host, sep, port_text = raw_value.rpartition(":")
    if not sep or not host or not port_text:
        raise ValueError(f"Invalid bind address: {bind_addr}")
    return host, int(port_text)


def is_tcp_bind_address_available(bind_addr: str) -> bool:
    """Return whether one TCP bind address looks available locally."""

    try:
        host, port = parse_host_port(bind_addr)
    except Exception:
        return False

    family = socket.AF_INET6 if ":" in host and host not in {"0.0.0.0", "*"} else socket.AF_INET
    probe_host = host if host != "*" else "0.0.0.0"
    with socket.socket(family, socket.SOCK_STREAM) as probe_socket:
        probe_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe_socket.bind((probe_host, port))
        except OSError as exc:
            # Non-root runtimes probing privileged ports (<1024) can fail with
            # EACCES/EPERM even when nothing is listening. In that case, fall
            # back to listener inspection rather than reporting a false conflict.
            if exc.errno in {errno.EACCES, errno.EPERM}:
                return inspect_tcp_listener_for_bind_addr(bind_addr) is None
            return False
    return True


def is_tcp_port_listening(port: int) -> bool:
    """Return whether any local TCP listener currently occupies ``port``."""

    return inspect_tcp_listener(port) is not None


def inspect_tcp_listener_for_bind_addr(bind_addr: str) -> PortListenerInfo | None:
    """Return best-effort listener diagnostics for one busy bind address."""

    try:
        _host, port = parse_host_port(bind_addr)
    except Exception:
        return None

    listener = inspect_tcp_listener(port)
    if listener is None:
        return None
    if listener.bind_addr:
        return listener
    return PortListenerInfo(
        port=listener.port,
        source=listener.source,
        bind_addr=bind_addr,
        local_address=listener.local_address,
        process_name=listener.process_name,
        pid=listener.pid,
    )


def inspect_tcp_listener(port: int) -> PortListenerInfo | None:
    """Return best-effort listener diagnostics for one local TCP port."""

    ss_listener = _inspect_tcp_listener_via_ss(port)
    if ss_listener is not None:
        return ss_listener
    return _inspect_tcp_listener_via_lsof(port)


def list_listening_tcp_pids(
    port: int,
    *,
    run_command: PortCommandRunner | None = None,
) -> list[int]:
    """Return PIDs listening on one local TCP port."""

    runner = run_command or _run_port_command
    try:
        proc = runner(["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN", "-Pn"])
        if proc.returncode == 0 and proc.stdout:
            return sorted(
                {
                    int(line.strip())
                    for line in proc.stdout.splitlines()
                    if line.strip().isdigit()
                }
            )
    except Exception:
        pass

    try:
        proc = runner(["ss", "-ltnp", f"sport = :{port}"])
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return sorted({int(m.group(1)) for m in re.finditer(r"pid=(\d+)", out)})
    except Exception:
        return []


def terminate_pids(
    pids: list[int] | tuple[int, ...],
    *,
    run_command: PortCommandRunner | None = None,
    grace_period_seconds: float = 1.0,
) -> bool:
    """Terminate one PID list with TERM then KILL if still present."""

    normalized_pids = [int(pid) for pid in pids if isinstance(pid, int) and pid > 0]
    if not normalized_pids:
        return True

    runner = run_command or _run_port_command
    for pid in normalized_pids:
        proc = runner(["kill", "-TERM", str(pid)])
        if proc.returncode not in (0, 1):
            return False

    if grace_period_seconds > 0:
        time.sleep(grace_period_seconds)

    for pid in normalized_pids:
        proc = runner(["kill", "-KILL", str(pid)])
        if proc.returncode not in (0, 1):
            return False
    return True


def _inspect_tcp_listener_via_ss(port: int) -> PortListenerInfo | None:
    """Inspect one local TCP port via ``ss``."""

    try:
        proc = subprocess.run(
            ["ss", "-ltnp", f"sport = :{port}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
    except Exception:
        return None

    combined_output = "\n".join(
        part.strip()
        for part in ((proc.stdout or "").strip(), (proc.stderr or "").strip())
        if part.strip()
    )
    if not combined_output:
        return None

    selected_line = ""
    for raw_line in combined_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "LISTEN" in line.upper() and f":{port}" in line:
            selected_line = line
            break
    if not selected_line and f":{port}" not in combined_output:
        return None

    local_address: str | None = None
    process_name: str | None = None
    pid_value: int | None = None
    if selected_line:
        parts = selected_line.split()
        if len(parts) >= 5:
            local_address = parts[4]
        process_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', selected_line)
        if process_match:
            process_name = process_match.group(1)
            try:
                pid_value = int(process_match.group(2))
            except ValueError:
                pid_value = None
        else:
            pid_match = re.search(r"pid=(\d+)", selected_line)
            if pid_match:
                try:
                    pid_value = int(pid_match.group(1))
                except ValueError:
                    pid_value = None

    return PortListenerInfo(
        port=port,
        source="ss",
        local_address=local_address,
        process_name=process_name,
        pid=pid_value,
    )


def _inspect_tcp_listener_via_lsof(port: int) -> PortListenerInfo | None:
    """Inspect one local TCP port via ``lsof``."""

    try:
        proc = subprocess.run(
            ["lsof", f"-iTCP:{port}", "-sTCP:LISTEN", "-Pn"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
    except Exception:
        return None

    stdout_text = (proc.stdout or "").strip()
    if not stdout_text:
        return None

    data_lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
    if len(data_lines) < 2:
        return PortListenerInfo(port=port, source="lsof")

    first_entry = data_lines[1]
    parts = first_entry.split()
    process_name = parts[0] if parts else None
    pid_value: int | None = None
    if len(parts) > 1 and parts[1].isdigit():
        pid_value = int(parts[1])
    local_address = parts[-2] if len(parts) >= 2 else None
    return PortListenerInfo(
        port=port,
        source="lsof",
        local_address=local_address,
        process_name=process_name,
        pid=pid_value,
    )


def _run_port_command(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one local command for port diagnostics with capture enabled."""

    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=2,
    )


__all__ = [
    "PortListenerInfo",
    "inspect_tcp_listener",
    "inspect_tcp_listener_for_bind_addr",
    "is_tcp_bind_address_available",
    "is_tcp_port_listening",
    "list_listening_tcp_pids",
    "parse_host_port",
    "terminate_pids",
]
