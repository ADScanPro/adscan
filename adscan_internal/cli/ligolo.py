"""Ligolo-ng CLI orchestration helpers."""

from __future__ import annotations

import shlex
from typing import Any, Protocol
from rich.table import Table

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_instruction,
    print_operation_header,
    print_success,
)
from adscan_internal.services.ligolo_service import (
    DEFAULT_LIGOLO_PROXY_API_ADDR,
    LigoloProxyService,
)


class LigoloShell(Protocol):
    """Shell protocol for Ligolo CLI helpers."""

    current_workspace_dir: str | None
    current_domain: str | None


def _require_workspace(shell: LigoloShell) -> str | None:
    """Return the current workspace directory or emit an actionable error."""

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if workspace_dir:
        return workspace_dir
    print_error("No active workspace is loaded.")
    print_instruction("Load or create a workspace before managing ligolo pivots.")
    return None


def _print_proxy_status(state: dict[str, Any]) -> None:
    """Render one compact Ligolo proxy status block."""

    details = {
        "Workspace": state.get("workspace_dir", "unknown"),
        "Domain": state.get("current_domain") or "none",
        "Status": state.get("status", "unknown"),
        "Alive": "yes" if state.get("alive") else "no",
        "PID": str(state.get("pid", "none")),
        "Listen": state.get("listen_addr", "unknown"),
        "API": state.get("api_laddr", "unknown"),
    }
    print_operation_header("Ligolo Proxy Status", details=details, icon="🧭")

    stdout_log = state.get("stdout_log")
    stderr_log = state.get("stderr_log")
    if stdout_log:
        print_info(f"Stdout Log: {mark_sensitive(str(stdout_log), 'path')}")
    if stderr_log:
        print_info(f"Stderr Log: {mark_sensitive(str(stderr_log), 'path')}")


def _print_tunnel_table(shell: LigoloShell, records: list[dict[str, Any]]) -> None:
    """Render one compact tunnel table."""

    if not records:
        print_info("No Ligolo tunnels are persisted for this workspace.")
        return
    console = getattr(shell, "console", None)
    if console is None:
        for record in records:
            print_info(
                " | ".join(
                    [
                        f"id={record.get('tunnel_id')}",
                        f"status={record.get('status')}",
                        f"pivot={record.get('pivot_host')}",
                        f"interface={record.get('interface_name')}",
                    ]
                )
            )
        return
    table = Table(title="Ligolo Tunnels", box=None)
    table.add_column("Tunnel ID")
    table.add_column("Status")
    table.add_column("Pivot Host")
    table.add_column("Interface")
    table.add_column("Routes")
    table.add_column("Target Preview")
    for record in records[:20]:
        targets = record.get("confirmed_targets") or []
        preview_hosts = []
        for target in targets[:3]:
            if isinstance(target, dict):
                for hostname in target.get("hostname_candidates", []):
                    hostname_text = str(hostname or "").strip()
                    if hostname_text and hostname_text not in preview_hosts:
                        preview_hosts.append(hostname_text)
        table.add_row(
            mark_sensitive(str(record.get("tunnel_id") or "unknown"), "text"),
            mark_sensitive(str(record.get("status") or "unknown"), "text"),
            mark_sensitive(str(record.get("pivot_host") or "unknown"), "hostname"),
            mark_sensitive(str(record.get("interface_name") or "unknown"), "text"),
            ", ".join(mark_sensitive(str(route), "text") for route in (record.get("routes") or [])[:3]) or "-",
            ", ".join(mark_sensitive(host, "hostname") for host in preview_hosts) or "-",
        )
    console.print(table)


def run_ligolo_command(shell: LigoloShell, args: str) -> None:
    """Run the ``ligolo`` command family."""

    workspace_dir = _require_workspace(shell)
    if workspace_dir is None:
        return

    argv = shlex.split(args or "")
    if not argv:
        print_error("Usage: ligolo <proxy|tunnel> ...")
        return

    command = argv[0].lower()
    service = LigoloProxyService(
        workspace_dir=workspace_dir,
        current_domain=getattr(shell, "current_domain", None),
    )

    if command == "tunnel":
        action = argv[1].lower() if len(argv) > 1 else "list"
        if action == "list":
            records = service.list_tunnel_records()
            print_operation_header(
                "Ligolo Tunnel Inventory",
                details={
                    "Workspace": workspace_dir,
                    "Domain": getattr(shell, "current_domain", None) or "none",
                    "Persisted Tunnels": str(len(records)),
                },
                icon="🧭",
            )
            _print_tunnel_table(shell, records)
            return
        if action == "status":
            if len(argv) < 3:
                print_error("Usage: ligolo tunnel status <tunnel_id>")
                return
            tunnel_id = argv[2]
            records = service.list_tunnel_records()
            record = next(
                (entry for entry in records if str(entry.get("tunnel_id") or "").strip() == tunnel_id),
                None,
            )
            if record is None:
                print_error(f"No Ligolo tunnel with ID '{tunnel_id}' exists in this workspace.")
                return
            print_operation_header(
                "Ligolo Tunnel Status",
                details={
                    "Workspace": workspace_dir,
                    "Domain": getattr(shell, "current_domain", None) or "none",
                    "Tunnel ID": tunnel_id,
                    "Status": record.get("status", "unknown"),
                    "Pivot Host": record.get("pivot_host", "unknown"),
                    "Interface": record.get("interface_name", "unknown"),
                },
                icon="🧭",
            )
            _print_tunnel_table(shell, [record])
            print_info_debug("[ligolo] Tunnel payload: " + str(mark_sensitive(str(record), "json")))
            return
        if action == "stop":
            if len(argv) < 3:
                print_error("Usage: ligolo tunnel stop <tunnel_id>")
                return
            tunnel_id = argv[2]
            try:
                record = service.stop_tunnel(tunnel_id=tunnel_id)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_error("Failed to stop the Ligolo tunnel.")
                print_exception(show_locals=False, exception=exc)
                return
            print_success(
                "Ligolo tunnel stopped. "
                f"Tunnel ID={mark_sensitive(str(record.get('tunnel_id') or tunnel_id), 'text')}"
            )
            return
        print_error(f"Unknown ligolo tunnel action '{action}'.")
        print_instruction("Use: ligolo tunnel <list|status|stop>")
        return

    if command != "proxy":
        print_error(f"Unknown ligolo command '{command}'.")
        print_instruction("Use: ligolo <proxy|tunnel> ...")
        return

    action = argv[1].lower() if len(argv) > 1 else "status"
    if action == "start":
        api_laddr = argv[3] if len(argv) > 3 else DEFAULT_LIGOLO_PROXY_API_ADDR
        try:
            listen_addr = argv[2] if len(argv) > 2 else service.resolve_default_listen_addr()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Failed to determine a default ligolo-ng listen address.")
            print_exception(show_locals=False, exception=exc)
            print_instruction("Inspect listeners with: ss -ltnp '( sport = :443 or sport = :80 )'")
            print_instruction(
                "If Windows egress allows another port, start the proxy explicitly: ligolo proxy start 0.0.0.0:<port>"
            )
            return
        print_operation_header(
            "Ligolo Proxy Start",
            details={
                "Workspace": workspace_dir,
                "Domain": getattr(shell, "current_domain", None) or "none",
                "Listen": listen_addr,
                "API": api_laddr,
                "Mode": "Daemon",
                "Egress Policy": "Prefer 443, fallback 80",
            },
            icon="🧭",
        )
        try:
            state = service.start_proxy(listen_addr=listen_addr, api_laddr=api_laddr)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Failed to start the ligolo-ng proxy.")
            print_exception(show_locals=False, exception=exc)
            return
        print_success(
            "Ligolo-ng proxy started. "
            f"Listen={mark_sensitive(str(state.get('listen_addr', 'unknown')), 'host')} "
            f"API={mark_sensitive(str(state.get('api_laddr', 'unknown')), 'host')}"
        )
        return

    if action == "stop":
        print_operation_header(
            "Ligolo Proxy Stop",
            details={
                "Workspace": workspace_dir,
                "Domain": getattr(shell, "current_domain", None) or "none",
            },
            icon="🧭",
        )
        try:
            state = service.stop_proxy()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Failed to stop the ligolo-ng proxy.")
            print_exception(show_locals=False, exception=exc)
            return
        print_success(
            "Ligolo-ng proxy stopped. "
            f"Previous PID={mark_sensitive(str(state.get('pid', 'unknown')), 'pid')}"
        )
        return

    if action == "status":
        state = service.get_status()
        _print_proxy_status(state)
        preview = service.build_debug_log_preview()
        if preview:
            print_info_debug("[ligolo] Output preview:\n" + preview)
        print_info_debug(
            "[ligolo] Status payload: "
            + str(mark_sensitive(str(state), "json"))
        )
        return

    if action == "logs":
        max_lines = 20
        if len(argv) > 2:
            try:
                max_lines = max(1, int(argv[2]))
            except ValueError:
                print_error("Log lines must be an integer.")
                return
        state = service.get_status()
        _print_proxy_status(state)
        logs = service.read_recent_logs(max_lines=max_lines)
        stdout_lines = logs.get("stdout") or []
        stderr_lines = logs.get("stderr") or []
        print_info(f"Recent Stdout Lines: {len(stdout_lines)}")
        for line in stdout_lines:
            print_info(line, spacing="none")
        print_info(f"Recent Stderr Lines: {len(stderr_lines)}")
        for line in stderr_lines:
            print_info(line, spacing="none")
        return

    print_error(f"Unknown ligolo proxy action '{action}'.")
    print_instruction("Use: ligolo proxy <start|stop|status|logs>")


__all__ = ["run_ligolo_command"]
