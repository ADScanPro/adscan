"""Ligolo-ng proxy lifecycle helpers.

This module manages the local Ligolo-ng proxy process as a workspace-scoped
runtime dependency. It intentionally avoids PTY automation and instead uses a
managed background process with persisted state and centralized ADscan-style
debug logging.

Important compatibility note:
- This service targets the pinned Ligolo-ng release managed by ADscan.
- Behaviour such as daemon startup, config handling, and the Web/API contract
  is implemented for Ligolo-ng ``v0.8.3``.
- The high-level features are documented upstream at:
  - https://docs.ligolo.ng/
  - https://docs.ligolo.ng/Config-File/
  - https://docs.ligolo.ng/webui/
- The exact API endpoints and payloads used here are not fully described in the
  public docs, so this service intentionally follows the upstream ``v0.8.3``
  source contract. Treat API compatibility as version-sensitive.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import time
import uuid
from urllib import error as urllib_error
from urllib import request as urllib_request
from typing import Any

from adscan_internal import print_info_debug, print_info_verbose
from adscan_core.linux_capabilities import (
    CAP_NET_BIND_SERVICE_BIT,
    binary_has_capability,
    process_has_capability,
)
from adscan_internal.ligolo_manager import (
    LIGOLO_NG_VERSION,
    get_current_ligolo_proxy_target,
    get_ligolo_proxy_local_path,
)
from adscan_core.port_diagnostics import (
    PortListenerInfo,
    inspect_tcp_listener_for_bind_addr,
    is_tcp_bind_address_available as _is_bind_address_available,
    parse_host_port as _parse_host_port,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.workspaces.io import read_json_file, write_json_file


DEFAULT_LIGOLO_PROXY_LISTEN_ADDR = "0.0.0.0:443"
DEFAULT_LIGOLO_PROXY_API_ADDR = "127.0.0.1:8080"
DEFAULT_LIGOLO_PROXY_LISTEN_CANDIDATES = ("0.0.0.0:443", "0.0.0.0:80")
_LIGOLO_PREVIEW_HEAD_LINES = 10
_LIGOLO_PREVIEW_TAIL_LINES = 10
_LIGOLO_STOP_WAIT_SECONDS = 5.0
_LIGOLO_START_STABILIZE_SECONDS = 0.75
_LIGOLO_PROXY_VERSION_TIMEOUT_SECONDS = 5.0
_LIGOLO_INTERACTIVE_BOOTSTRAP_MARKERS = (
    "Enable Ligolo-ng WebUI?",
    "daemon configuration file not found. Creating a new one...",
)
LIGOLO_DOCS_OVERVIEW_URL = "https://docs.ligolo.ng/"
LIGOLO_DOCS_CONFIG_URL = "https://docs.ligolo.ng/Config-File/"
LIGOLO_DOCS_WEB_URL = "https://docs.ligolo.ng/webui/"
LIGOLO_API_CONTRACT_VERSION = LIGOLO_NG_VERSION
LIGOLO_API_CONTRACT_ENDPOINTS: tuple[str, ...] = (
    "POST /api/auth",
    "GET /api/v1/ping",
    "GET /api/v1/agents",
    "GET /api/v1/interfaces",
    "POST /api/v1/interfaces",
    "POST /api/v1/routes",
    "POST /api/v1/tunnel/:id",
    "DELETE /api/v1/tunnel/:id",
)


@dataclass(frozen=True, slots=True)
class LigoloProxyPaths:
    """Filesystem paths used by one workspace-scoped Ligolo proxy."""

    root_dir: Path
    state_file: Path
    config_file: Path
    auth_file: Path
    tunnels_file: Path
    stdout_log: Path
    stderr_log: Path
    api_log: Path


def _utc_now_iso() -> str:
    """Return the current UTC timestamp as an ISO-8601 string."""

    return datetime.now(timezone.utc).isoformat()


def _is_pid_running(pid: int | None) -> bool:
    """Return whether one PID currently exists."""

    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _inspect_bind_conflict(bind_addr: str) -> PortListenerInfo | None:
    """Return best-effort listener diagnostics for one busy bind address."""

    return inspect_tcp_listener_for_bind_addr(bind_addr)


def _read_log_lines_preview(path: Path, *, head: int, tail: int) -> tuple[list[str], list[str], int]:
    """Return head/tail preview lines plus total non-empty line count for one log file."""

    if not path.is_file():
        return [], [], 0

    first_lines: list[str] = []
    tail_lines: deque[str] = deque(maxlen=tail)
    total_lines = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            total_lines += 1
            if len(first_lines) < head:
                first_lines.append(line)
            tail_lines.append(line)

    return first_lines, list(tail_lines), total_lines


def _build_detached_process_preview(stdout_log: Path, stderr_log: Path) -> str:
    """Build an ADscan-style preview from detached stdout/stderr log files."""

    preview_lines: list[str] = []

    stdout_head, stdout_tail, stdout_total = _read_log_lines_preview(
        stdout_log,
        head=_LIGOLO_PREVIEW_HEAD_LINES,
        tail=_LIGOLO_PREVIEW_TAIL_LINES,
    )
    if stdout_head:
        preview_lines.append("STDOUT (head):")
        preview_lines.extend(stdout_head)
    omitted_stdout = stdout_total - len(stdout_head) - len(stdout_tail)
    if omitted_stdout > 0:
        preview_lines.append(f"... ({omitted_stdout} stdout line(s) omitted) ...")
    if stdout_tail and stdout_tail != stdout_head:
        preview_lines.append("STDOUT (tail):")
        preview_lines.extend(stdout_tail)

    stderr_head, stderr_tail, stderr_total = _read_log_lines_preview(
        stderr_log,
        head=_LIGOLO_PREVIEW_HEAD_LINES,
        tail=_LIGOLO_PREVIEW_TAIL_LINES,
    )
    if stderr_head:
        preview_lines.append("STDERR (head):")
        preview_lines.extend(stderr_head)
    omitted_stderr = stderr_total - len(stderr_head) - len(stderr_tail)
    if omitted_stderr > 0:
        preview_lines.append(f"... ({omitted_stderr} stderr line(s) omitted) ...")
    if stderr_tail and stderr_tail != stderr_head:
        preview_lines.append("STDERR (tail):")
        preview_lines.extend(stderr_tail)

    return "\n".join(preview_lines)


def _extract_ligolo_version(output: str) -> str | None:
    """Extract one ``x.y.z`` Ligolo version from command output."""

    match = re.search(r"\b(\d+\.\d+\.\d+)\b", str(output or ""))
    if not match:
        return None
    return match.group(1)


class LigoloProxyService:
    """Manage one workspace-scoped Ligolo-ng proxy process.

    The service intentionally assumes the API contract exposed by Ligolo-ng
    ``v0.8.3``. Before using the API backend we validate the local proxy binary
    version so callers fail early if a mismatched release is present.
    """

    def __init__(self, *, workspace_dir: str, current_domain: str | None = None) -> None:
        self.workspace_dir = Path(workspace_dir).expanduser().resolve()
        self.current_domain = str(current_domain or "").strip() or None
        ligolo_dir = self.workspace_dir / "ligolo"
        self.paths = LigoloProxyPaths(
            root_dir=ligolo_dir,
            state_file=ligolo_dir / "proxy_state.json",
            config_file=ligolo_dir / "proxy_config.yaml",
            auth_file=ligolo_dir / "proxy_api_auth.json",
            tunnels_file=ligolo_dir / "tunnels_state.json",
            stdout_log=ligolo_dir / "proxy.stdout.log",
            stderr_log=ligolo_dir / "proxy.stderr.log",
            api_log=ligolo_dir / "proxy.api.log",
        )
        self._api_token: str | None = None
        self._api_contract_validated = False

    def ensure_runtime_dir(self) -> None:
        """Ensure the workspace runtime directory exists."""

        self.paths.root_dir.mkdir(parents=True, exist_ok=True)

    def get_proxy_binary_path(self) -> Path:
        """Return the local pinned proxy binary path or raise one actionable error."""

        local_os, local_arch = get_current_ligolo_proxy_target()
        proxy_path = get_ligolo_proxy_local_path(target_os=local_os, arch=local_arch)
        if proxy_path is None:
            raise FileNotFoundError(
                f"ligolo-ng proxy not found for {local_os}/{local_arch}"
            )
        return proxy_path

    def get_proxy_version(self) -> str | None:
        """Return the detected proxy version, if the binary reports one."""

        proxy_path = self.get_proxy_binary_path()
        for args in ([str(proxy_path), "-version"], [str(proxy_path), "--version"]):
            try:
                result = subprocess.run(
                    args,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=_LIGOLO_PROXY_VERSION_TIMEOUT_SECONDS,
                )
            except Exception:
                continue
            combined_output = "\n".join(
                part.strip()
                for part in [result.stdout, result.stderr]
                if str(part).strip()
            )
            version_text = _extract_ligolo_version(combined_output)
            if version_text:
                return version_text
        return None

    def validate_proxy_api_contract(self) -> None:
        """Ensure the local proxy binary matches the API contract assumed by ADscan."""

        if self._api_contract_validated:
            return
        detected_version = self.get_proxy_version()
        if detected_version and detected_version != LIGOLO_API_CONTRACT_VERSION:
            raise RuntimeError(
                "Ligolo-ng proxy version mismatch. "
                f"ADscan expects {LIGOLO_API_CONTRACT_VERSION} for the managed API contract, "
                f"but the local proxy reports {detected_version}. "
                "Rebuild/update the runtime or point ADSCAN_LIGOLO_PROXY_PATH to the pinned release."
            )
        if detected_version is None:
            print_info_debug(
                "[ligolo] Proxy version could not be determined from the local binary. "
                f"Proceeding with the pinned API contract assumption for v{LIGOLO_API_CONTRACT_VERSION}."
            )
        self._api_contract_validated = True

    def load_state(self) -> dict[str, Any] | None:
        """Load persisted state from disk, if any."""

        if not self.paths.state_file.is_file():
            return None
        payload = read_json_file(str(self.paths.state_file))
        if not isinstance(payload, dict):
            return None
        return payload

    def save_state(self, state: dict[str, Any]) -> None:
        """Persist state to disk with stable JSON formatting."""

        self.ensure_runtime_dir()
        write_json_file(str(self.paths.state_file), state)

    def load_tunnels_state(self) -> list[dict[str, Any]]:
        """Load persisted tunnel records from disk."""

        if not self.paths.tunnels_file.is_file():
            return []
        try:
            with self.paths.tunnels_file.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return []
        return [entry for entry in payload if isinstance(entry, dict)]

    def save_tunnels_state(self, tunnels: list[dict[str, Any]]) -> None:
        """Persist all tunnel records for the current workspace."""

        self.ensure_runtime_dir()
        with self.paths.tunnels_file.open("w", encoding="utf-8") as handle:
            json.dump(tunnels, handle, indent=2, sort_keys=False)
            handle.write("\n")

    def append_tunnel_state(self, record: dict[str, Any]) -> dict[str, Any]:
        """Append one tunnel record to the workspace tunnel state and return it."""

        tunnels = self.load_tunnels_state()
        stored_record = dict(record)
        if not str(stored_record.get("tunnel_id") or "").strip():
            stored_record["tunnel_id"] = uuid.uuid4().hex[:12]
        stored_record.setdefault("status", "running")
        stored_record["updated_at"] = _utc_now_iso()
        tunnels.append(stored_record)
        self.save_tunnels_state(tunnels)
        return dict(stored_record)

    def update_tunnel_record(self, *, tunnel_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        """Merge updates into one persisted tunnel record and return the result."""

        needle = str(tunnel_id or "").strip()
        if not needle or not isinstance(updates, dict):
            return None
        records = self.load_tunnels_state()
        for index, record in enumerate(records):
            if str(record.get("tunnel_id") or "").strip() != needle:
                continue
            updated_record = dict(record)
            updated_record.update(updates)
            updated_record["updated_at"] = _utc_now_iso()
            records[index] = updated_record
            self.save_tunnels_state(records)
            return dict(updated_record)
        return None

    def get_tunnel_record(self, tunnel_id: str) -> dict[str, Any] | None:
        """Return one persisted tunnel record by identifier."""

        needle = str(tunnel_id or "").strip()
        if not needle:
            return None
        for record in self.load_tunnels_state():
            if str(record.get("tunnel_id") or "").strip() == needle:
                return dict(record)
        return None

    def list_tunnel_records(self) -> list[dict[str, Any]]:
        """Return normalized tunnel records enriched with current agent runtime state."""

        records = []
        agents_by_id = {
            int(agent.get("id", -1)): agent
            for agent in self.list_agents()
        }
        for record in self.load_tunnels_state():
            normalized = dict(record)
            tunnel_id = str(normalized.get("tunnel_id") or "").strip()
            if not tunnel_id:
                tunnel_id = uuid.uuid4().hex[:12]
                normalized["tunnel_id"] = tunnel_id
            agent_payload = normalized.get("agent")
            agent_id = None
            if isinstance(agent_payload, dict):
                try:
                    agent_id = int(agent_payload.get("id"))
                except (TypeError, ValueError):
                    agent_id = None
            runtime_agent = agents_by_id.get(agent_id) if agent_id is not None else None
            normalized["alive"] = bool(runtime_agent)
            normalized["runtime_agent"] = runtime_agent
            if runtime_agent:
                normalized["status"] = "running" if runtime_agent.get("running") else "connected"
            elif str(normalized.get("status") or "").strip().lower() == "running":
                normalized["status"] = "disconnected"
            records.append(normalized)
        return records

    def stop_tunnel(self, *, tunnel_id: str) -> dict[str, Any]:
        """Stop one persisted tunnel by ID and update workspace state."""

        records = self.load_tunnels_state()
        target_index: int | None = None
        target_record: dict[str, Any] | None = None
        for index, record in enumerate(records):
            if str(record.get("tunnel_id") or "").strip() == str(tunnel_id or "").strip():
                target_index = index
                target_record = dict(record)
                break
        if target_index is None or target_record is None:
            raise RuntimeError(f"No Ligolo tunnel with ID '{tunnel_id}' exists in this workspace.")

        agent_payload = target_record.get("agent")
        try:
            agent_id = int(agent_payload.get("id")) if isinstance(agent_payload, dict) else None
        except (TypeError, ValueError):
            agent_id = None
        if agent_id is not None:
            self._api_request(method="DELETE", path=f"/api/v1/tunnel/{agent_id}")

        target_record["status"] = "stopped"
        target_record["stopped_at"] = _utc_now_iso()
        target_record["updated_at"] = _utc_now_iso()
        records[target_index] = target_record
        self.save_tunnels_state(records)
        return target_record

    def _ensure_api_credentials(self) -> dict[str, str]:
        """Create or load local API credentials for the workspace proxy."""

        existing = read_json_file(str(self.paths.auth_file)) if self.paths.auth_file.is_file() else None
        if isinstance(existing, dict):
            username = str(existing.get("username") or "").strip()
            password = str(existing.get("password") or "").strip()
            if username and password:
                return {"username": username, "password": password}

        credentials = {
            "username": "adscan",
            "password": secrets.token_urlsafe(24),
        }
        self.ensure_runtime_dir()
        write_json_file(str(self.paths.auth_file), credentials)
        try:
            os.chmod(self.paths.auth_file, 0o600)
        except OSError:
            pass
        return credentials

    def _write_managed_config(
        self,
        *,
        api_laddr: str,
        selfcert_domain: str,
    ) -> None:
        """Write one non-interactive proxy config with API enabled."""

        credentials = self._ensure_api_credentials()
        config_text = "\n".join(
            [
                "web:",
                "  enabled: true",
                "  enableui: false",
                f"  listen: {api_laddr}",
                "  debug: false",
                f"  logfile: {self.paths.api_log}",
                "  behindreverseproxy: false",
                "  trustedproxies:",
                "    - 127.0.0.1",
                "  corsallowedorigin:",
                f"    - http://{api_laddr}",
                f"  secret: {secrets.token_hex(32)}",
                "  tls:",
                "    enabled: false",
                "    selfcert: false",
                "    autocert: false",
                f"    selfcertdomain: {selfcert_domain}",
                "  users:",
                f"    {credentials['username']}: {credentials['password']}",
                "",
            ]
        )
        self.ensure_runtime_dir()
        self.paths.config_file.write_text(config_text, encoding="utf-8")
        try:
            os.chmod(self.paths.config_file, 0o600)
        except OSError:
            pass
        try:
            config_size = self.paths.config_file.stat().st_size
        except OSError:
            config_size = -1
        print_info_debug(
            "[ligolo] Managed config written: "
            f"path={mark_sensitive(str(self.paths.config_file), 'path')} "
            f"size={config_size} "
            f"api_laddr={api_laddr}"
        )

    def build_proxy_command(
        self,
        *,
        listen_addr: str = DEFAULT_LIGOLO_PROXY_LISTEN_ADDR,
        api_laddr: str = DEFAULT_LIGOLO_PROXY_API_ADDR,
        selfcert_domain: str = "ligolo",
    ) -> list[str]:
        """Build the exact Ligolo-ng proxy command."""

        proxy_path = self.get_proxy_binary_path()

        return [
            str(proxy_path),
            "-daemon",
            "-nobanner",
            "-config",
            self.paths.config_file.name,
            "-selfcert",
            "-selfcert-domain",
            selfcert_domain,
            "-laddr",
            listen_addr,
            "-api-laddr",
            api_laddr,
        ]

    def _assert_bind_permissions_for_listen_addr(self, listen_addr: str) -> None:
        """Fail early when a privileged Ligolo port cannot be bound by the runtime."""

        _host, port = _parse_host_port(listen_addr)
        if int(port) >= 1024:
            return
        proxy_path = str(self.get_proxy_binary_path())
        process_has_bind_service = process_has_capability(CAP_NET_BIND_SERVICE_BIT)
        binary_has_bind_service = binary_has_capability(proxy_path, "cap_net_bind_service")
        print_info_debug(
            "[ligolo] Privileged bind diagnostics: "
            f"listen_addr={listen_addr} "
            f"process_cap_net_bind_service={process_has_bind_service} "
            f"proxy_binary_has_cap_net_bind_service={binary_has_bind_service}"
        )
        if process_has_bind_service or binary_has_bind_service:
            return
        raise RuntimeError(
            "Ligolo proxy is configured to use a privileged port "
            f"({listen_addr}), but neither the ADscan process nor the ligolo-ng proxy binary "
            "has CAP_NET_BIND_SERVICE. Rebuild the runtime image with "
            "'setcap cap_net_admin,cap_net_bind_service+ep' on the ligolo proxy binary, "
            "grant CAP_NET_BIND_SERVICE to the container, or use a custom listen address >=1024 "
            "after verifying pivot egress."
        )

    def resolve_default_listen_addr(self) -> str:
        """Return the best default proxy bind address for Windows egress."""

        conflict_summaries: list[str] = []
        for candidate in DEFAULT_LIGOLO_PROXY_LISTEN_CANDIDATES:
            if _is_bind_address_available(candidate):
                print_info_debug(f"[ligolo] Selected default listen address: {candidate}")
                return candidate
            conflict = _inspect_bind_conflict(candidate)
            if conflict is not None:
                summary = conflict.render_summary()
                conflict_summaries.append(summary)
                print_info_debug(
                    "[ligolo] Default listen candidate unavailable: "
                    + str(mark_sensitive(f"{candidate} -> {summary}", "detail"))
                )
            else:
                conflict_summaries.append(f"{candidate} -> busy (listener details unavailable)")
                print_info_debug(
                    "[ligolo] Default listen candidate unavailable: "
                    + str(mark_sensitive(f"{candidate} -> busy (listener details unavailable)", "detail"))
                )

        tried = ", ".join(DEFAULT_LIGOLO_PROXY_LISTEN_CANDIDATES)
        host_network_note = ""
        if os.environ.get("ADSCAN_CONTAINER_RUNTIME") == "1":
            host_network_note = (
                " ADscan Docker runtime uses --network host, so listeners on the base host "
                "also occupy these ports inside the container."
            )
        occupancy_text = ""
        if conflict_summaries:
            occupancy_text = " Conflicts: " + "; ".join(conflict_summaries) + "."
        raise RuntimeError(
            "No default ligolo egress port is available. "
            f"Tried: {tried}.{occupancy_text}{host_network_note} "
            "Stop the conflicting listener and retry, or specify a custom listen address explicitly "
            "after verifying that the pivot host can egress to that port."
        )

    def _build_running_state(
        self,
        *,
        pid: int,
        command: list[str],
        listen_addr: str,
        api_laddr: str,
        selfcert_domain: str,
    ) -> dict[str, Any]:
        """Build one persisted running-state payload."""

        return {
            "api_laddr": api_laddr,
            "command": list(command),
            "config_file": str(self.paths.config_file),
            "current_domain": self.current_domain,
            "listen_addr": listen_addr,
            "pid": pid,
            "proxy_path": command[0],
            "selfcert_domain": selfcert_domain,
            "started_at": _utc_now_iso(),
            "status": "running",
            "stderr_log": str(self.paths.stderr_log),
            "stdout_log": str(self.paths.stdout_log),
            "updated_at": _utc_now_iso(),
            "workspace_dir": str(self.workspace_dir),
        }

    def _emit_command_debug(self, command: list[str], *, cwd: Path | None = None) -> None:
        """Emit the exact proxy command through ADscan debug logging."""

        command_text = shlex.join(command)
        if cwd is not None:
            command_text += f" (cwd={cwd})"
        print_info_debug(
            "[ligolo] Command: " + str(mark_sensitive(command_text, "command"))
        )

    def _read_combined_proxy_logs(self) -> str:
        """Return current combined stdout/stderr text for startup diagnostics."""

        parts: list[str] = []
        for path in (self.paths.stdout_log, self.paths.stderr_log):
            if not path.is_file():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if content.strip():
                parts.append(content)
        return "\n".join(parts)

    def _detect_interactive_bootstrap_issue(self) -> str | None:
        """Return one diagnostic string when Ligolo entered interactive first-run mode."""

        combined_logs = self._read_combined_proxy_logs()
        for marker in _LIGOLO_INTERACTIVE_BOOTSTRAP_MARKERS:
            if marker in combined_logs:
                return marker
        return None

    def _emit_detached_result_debug(
        self,
        *,
        pid: int | None,
        elapsed_seconds: float,
        returncode: int | None = None,
    ) -> None:
        """Emit a detached-process result summary and log preview."""

        stdout_head, stdout_tail, stdout_total = _read_log_lines_preview(
            self.paths.stdout_log,
            head=_LIGOLO_PREVIEW_HEAD_LINES,
            tail=_LIGOLO_PREVIEW_TAIL_LINES,
        )
        stderr_head, stderr_tail, stderr_total = _read_log_lines_preview(
            self.paths.stderr_log,
            head=_LIGOLO_PREVIEW_HEAD_LINES,
            tail=_LIGOLO_PREVIEW_TAIL_LINES,
        )
        print_info_debug(
            "[ligolo] Result: "
            f"pid={pid if pid is not None else 'unknown'}, "
            f"returncode={returncode if returncode is not None else 'running'}, "
            f"stdout_lines={stdout_total}, stderr_lines={stderr_total}, "
            f"duration={elapsed_seconds:.3f}s"
        )
        preview = _build_detached_process_preview(self.paths.stdout_log, self.paths.stderr_log)
        if preview:
            print_info_debug("[ligolo] Output preview:\n" + preview)

    def start_proxy(
        self,
        *,
        listen_addr: str = DEFAULT_LIGOLO_PROXY_LISTEN_ADDR,
        api_laddr: str = DEFAULT_LIGOLO_PROXY_API_ADDR,
        selfcert_domain: str = "ligolo",
    ) -> dict[str, Any]:
        """Start the workspace-scoped Ligolo proxy in daemon mode."""

        existing_state = self.load_state() or {}
        if _is_pid_running(existing_state.get("pid")):
            raise RuntimeError("ligolo-ng proxy is already running for this workspace")

        self.ensure_runtime_dir()
        self.validate_proxy_api_contract()
        self._assert_bind_permissions_for_listen_addr(listen_addr)
        self._write_managed_config(api_laddr=api_laddr, selfcert_domain=selfcert_domain)
        command = self.build_proxy_command(
            listen_addr=listen_addr,
            api_laddr=api_laddr,
            selfcert_domain=selfcert_domain,
        )
        print_info_debug(
            "[ligolo] API contract: "
            f"version={LIGOLO_API_CONTRACT_VERSION} "
            f"endpoints={', '.join(LIGOLO_API_CONTRACT_ENDPOINTS)}"
        )
        self._emit_command_debug(command, cwd=self.paths.root_dir)

        started_at = time.perf_counter()
        with self.paths.stdout_log.open("a", encoding="utf-8") as stdout_handle, self.paths.stderr_log.open(
            "a", encoding="utf-8"
        ) as stderr_handle:
            process = subprocess.Popen(  # noqa: S603
                command,
                stdout=stdout_handle,
                stderr=stderr_handle,
                text=True,
                start_new_session=True,
                cwd=str(self.paths.root_dir),
            )

        time.sleep(_LIGOLO_START_STABILIZE_SECONDS)
        elapsed_seconds = max(0.0, time.perf_counter() - started_at)
        returncode = process.poll()
        self._emit_detached_result_debug(
            pid=process.pid,
            elapsed_seconds=elapsed_seconds,
            returncode=returncode,
        )

        interactive_marker = self._detect_interactive_bootstrap_issue()
        if interactive_marker:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except OSError:
                pass
            failed_state = self._build_running_state(
                pid=process.pid,
                command=command,
                listen_addr=listen_addr,
                api_laddr=api_laddr,
                selfcert_domain=selfcert_domain,
            )
            failed_state["status"] = "failed"
            failed_state["failure_reason"] = "interactive_bootstrap"
            failed_state["updated_at"] = _utc_now_iso()
            self.save_state(failed_state)
            raise RuntimeError(
                "Ligolo proxy entered interactive first-run bootstrap instead of loading the managed "
                "config, so the Web/API backend never started. "
                f"Detected marker: {interactive_marker}. "
                "This usually means the config path was not resolved by Ligolo or the config file was not "
                "accepted. ADscan now launches Ligolo from the workspace runtime directory with a relative "
                "config path. Retry the tunnel workflow."
            )

        if returncode is not None:
            failed_state = self._build_running_state(
                pid=process.pid,
                command=command,
                listen_addr=listen_addr,
                api_laddr=api_laddr,
                selfcert_domain=selfcert_domain,
            )
            failed_state["status"] = "failed"
            failed_state["last_exit_code"] = int(returncode)
            failed_state["updated_at"] = _utc_now_iso()
            self.save_state(failed_state)
            raise RuntimeError(
                f"ligolo-ng proxy exited during startup (exit_code={returncode})"
            )

        running_state = self._build_running_state(
            pid=process.pid,
            command=command,
            listen_addr=listen_addr,
            api_laddr=api_laddr,
            selfcert_domain=selfcert_domain,
        )
        self.save_state(running_state)
        self.wait_for_api_ready()
        return running_state

    def _get_api_base_url(self) -> str:
        """Return the full base URL for the workspace proxy API."""

        state = self.get_status()
        api_laddr = str(state.get("api_laddr") or "").strip()
        if not api_laddr:
            raise RuntimeError("Ligolo-ng proxy API address is not available in workspace state.")
        return f"http://{api_laddr}"

    def _emit_api_debug(
        self,
        *,
        method: str,
        url: str,
        payload: dict[str, Any] | None,
        status_code: int | None,
        response_text: str,
        elapsed_seconds: float,
    ) -> None:
        """Emit ADscan-style debug logging for one Ligolo API request."""

        command_repr = f"{method.upper()} {url}"
        if payload is not None:
            command_repr += f" payload={json.dumps(payload, sort_keys=True)}"
        print_info_debug("[ligolo] Command: " + str(mark_sensitive(command_repr, "command")))

        response_lines = [line for line in (response_text or "").splitlines() if line.strip()]
        stdout_count = len(response_lines) if status_code and status_code < 400 else 0
        stderr_count = len(response_lines) if status_code and status_code >= 400 else 0
        print_info_debug(
            "[ligolo] Result: "
            f"status_code={status_code if status_code is not None else 'error'}, "
            f"stdout_lines={stdout_count}, stderr_lines={stderr_count}, "
            f"duration={elapsed_seconds:.3f}s"
        )
        if response_lines:
            head_lines = response_lines[:_LIGOLO_PREVIEW_HEAD_LINES]
            tail_lines = response_lines[-_LIGOLO_PREVIEW_TAIL_LINES:]
            preview_lines = ["STDOUT (head):"]
            preview_lines.extend(head_lines)
            omitted = len(response_lines) - len(head_lines) - len(tail_lines)
            if omitted > 0:
                preview_lines.append(f"... ({omitted} response line(s) omitted) ...")
            if tail_lines != head_lines:
                preview_lines.append("STDOUT (tail):")
                preview_lines.extend(tail_lines)
            print_info_debug("[ligolo] Output preview:\n" + "\n".join(preview_lines))

    def _api_request(
        self,
        *,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        authenticated: bool = True,
    ) -> dict[str, Any] | list[Any]:
        """Execute one HTTP request against the managed Ligolo API."""

        self.validate_proxy_api_contract()
        url = self._get_api_base_url().rstrip("/") + path
        body_bytes = None
        headers = {"Content-Type": "application/json"}
        if payload is not None:
            body_bytes = json.dumps(payload).encode("utf-8")
        if authenticated:
            token = self._api_token or self._authenticate_api()
            headers["Authorization"] = token

        request = urllib_request.Request(
            url,
            data=body_bytes,
            headers=headers,
            method=method.upper(),
        )
        started_at = time.perf_counter()
        response_text = ""
        status_code: int | None = None
        try:
            with urllib_request.urlopen(request, timeout=10) as response:
                response_text = response.read().decode("utf-8", errors="replace")
                status_code = int(getattr(response, "status", 200))
        except urllib_error.HTTPError as exc:
            response_text = exc.read().decode("utf-8", errors="replace")
            status_code = int(exc.code)
            self._emit_api_debug(
                method=method,
                url=url,
                payload=payload,
                status_code=status_code,
                response_text=response_text,
                elapsed_seconds=max(0.0, time.perf_counter() - started_at),
            )
            raise RuntimeError(f"Ligolo API request failed ({method.upper()} {path}): HTTP {exc.code}")
        except Exception as exc:
            self._emit_api_debug(
                method=method,
                url=url,
                payload=payload,
                status_code=None,
                response_text=str(exc),
                elapsed_seconds=max(0.0, time.perf_counter() - started_at),
            )
            raise RuntimeError(f"Ligolo API request failed ({method.upper()} {path}): {exc}") from exc

        self._emit_api_debug(
            method=method,
            url=url,
            payload=payload,
            status_code=status_code,
            response_text=response_text,
            elapsed_seconds=max(0.0, time.perf_counter() - started_at),
        )
        parsed = json.loads(response_text) if response_text.strip() else {}
        if isinstance(parsed, (dict, list)):
            return parsed
        raise RuntimeError(f"Ligolo API returned an unexpected payload for {path}.")

    def _authenticate_api(self) -> str:
        """Authenticate against the workspace API and cache the bearer token."""

        credentials = self._ensure_api_credentials()
        payload = self._api_request(
            method="POST",
            path="/api/auth",
            payload={"Username": credentials["username"], "Password": credentials["password"]},
            authenticated=False,
        )
        if not isinstance(payload, dict):
            raise RuntimeError("Ligolo API authentication returned an unexpected payload.")
        token = str(payload.get("token") or "").strip()
        if not token:
            raise RuntimeError("Ligolo API authentication did not return a JWT token.")
        self._api_token = token
        return token

    def wait_for_api_ready(self, *, timeout_seconds: float = 15.0) -> None:
        """Poll the API until it becomes responsive."""

        deadline = time.time() + timeout_seconds
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                payload = self._api_request(method="GET", path="/api/v1/ping")
                if isinstance(payload, dict) and str(payload.get("message") or "").strip().lower() == "pong":
                    return
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                time.sleep(0.5)
                continue
        if last_error is not None:
            raise RuntimeError(f"Ligolo API did not become ready: {last_error}") from last_error
        raise RuntimeError("Ligolo API did not become ready within the expected timeout.")

    def get_server_fingerprint(self) -> str:
        """Return the SHA-256 fingerprint of the proxy TLS certificate."""

        state = self.get_status()
        listen_addr = str(state.get("listen_addr") or "").strip()
        if not listen_addr:
            raise RuntimeError("Ligolo proxy listen address is not available.")
        host, port = _parse_host_port(listen_addr)
        connect_host = "127.0.0.1" if host in {"0.0.0.0", "*"} else host
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((connect_host, port), timeout=5.0) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname="ligolo") as tls_socket:
                certificate = tls_socket.getpeercert(binary_form=True)
        if not certificate:
            raise RuntimeError("Ligolo proxy did not present a TLS certificate.")
        return hashlib.sha256(certificate).hexdigest().upper()

    def list_agents(self) -> list[dict[str, Any]]:
        """Return normalized agent entries from the Ligolo API."""

        payload = self._api_request(method="GET", path="/api/v1/agents")
        if not isinstance(payload, dict):
            raise RuntimeError("Ligolo API returned an unexpected agent payload.")
        agents: list[dict[str, Any]] = []
        for agent_id_text, entry in payload.items():
            if not isinstance(entry, dict):
                continue
            try:
                agent_id = int(agent_id_text)
            except (TypeError, ValueError):
                continue
            agents.append(
                {
                    "id": agent_id,
                    "name": str(entry.get("Name") or "").strip(),
                    "session_id": str(entry.get("SessionID") or "").strip(),
                    "remote_addr": str(entry.get("RemoteAddr") or "").strip(),
                    "interface": str(entry.get("Interface") or "").strip(),
                    "running": bool(entry.get("Running")),
                }
            )
        return sorted(agents, key=lambda item: int(item.get("id", 0)))

    def wait_for_new_agent(
        self,
        *,
        known_session_ids: set[str],
        timeout_seconds: float = 25.0,
    ) -> dict[str, Any]:
        """Wait for one newly connected agent that is not in the known session set."""

        print_info_verbose(
            f"Waiting for Ligolo agent to connect (timeout {timeout_seconds:.0f}s)…"
        )
        deadline = time.time() + timeout_seconds
        last_agents: list[dict[str, Any]] = []
        while time.time() < deadline:
            agents = self.list_agents()
            last_agents = agents
            for agent in agents:
                session_id = str(agent.get("session_id") or "").strip()
                if session_id and session_id not in known_session_ids:
                    print_info_verbose(
                        f"Agent connected: id={agent.get('id')} "
                        f"name={agent.get('name')!r} "
                        f"remote={agent.get('remote_addr')}"
                    )
                    return agent
            time.sleep(1.0)
        observed = ", ".join(
            f"{agent.get('id')}:{agent.get('session_id') or 'unknown'}" for agent in last_agents
        ) or "none"
        raise RuntimeError(f"No new Ligolo agent connected within timeout. Observed agents: {observed}")

    def get_interface_state(self, interface_name: str) -> dict[str, Any] | None:
        """Return one normalized interface state payload from the API."""

        payload = self._api_request(method="GET", path="/api/v1/interfaces")
        if not isinstance(payload, dict):
            return None
        interface_payload = payload.get(interface_name)
        return interface_payload if isinstance(interface_payload, dict) else None

    def _list_active_route_interfaces(self, route: str) -> list[str]:
        """Return local interface names currently owning one route in the kernel table."""

        ip_binary = shutil.which("ip")
        if ip_binary is None or not route:
            return []
        try:
            result = subprocess.run(
                [ip_binary, "-o", "route", "show", "exact", route],
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
        except Exception as exc:
            print_info_debug(f"[ligolo] Failed to inspect kernel route {route}: {exc}")
            return []
        if result.returncode != 0:
            stderr_text = str(result.stderr or "").strip()
            if stderr_text:
                print_info_debug(f"[ligolo] Kernel route lookup for {route} failed: {stderr_text}")
            return []

        interfaces: list[str] = []
        for raw_line in str(result.stdout or "").splitlines():
            match = re.search(r"\bdev\s+(\S+)", raw_line)
            if not match:
                continue
            iface_name = str(match.group(1) or "").strip()
            if iface_name and iface_name not in interfaces:
                interfaces.append(iface_name)
        if interfaces:
            print_info_debug(f"[ligolo] Kernel route owners for {route}: {interfaces}")
        return interfaces

    def _delete_kernel_route(self, *, route: str, interface_name: str) -> bool:
        """Best-effort delete of one local kernel route bound to one interface."""

        ip_binary = shutil.which("ip")
        if ip_binary is None or not route or not interface_name:
            return False
        try:
            result = subprocess.run(
                [ip_binary, "route", "del", route, "dev", interface_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
        except Exception as exc:
            print_info_debug(f"[ligolo] Failed to delete kernel route {route} on {interface_name}: {exc}")
            return False
        if result.returncode == 0:
            print_info_verbose(f"Route {route}: removed stale kernel route on {interface_name!r}.")
            return True
        stderr_text = str(result.stderr or "").strip()
        if stderr_text:
            print_info_debug(
                f"[ligolo] Kernel route deletion failed for {route} on {interface_name}: {stderr_text}"
            )
        return False

    def _delete_kernel_interface(self, interface_name: str) -> bool:
        """Best-effort delete of one local kernel TUN interface."""

        ip_binary = shutil.which("ip")
        if ip_binary is None or not interface_name:
            return False
        try:
            result = subprocess.run(
                [ip_binary, "link", "delete", interface_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
        except Exception as exc:
            print_info_debug(f"[ligolo] Failed to delete kernel interface {interface_name}: {exc}")
            return False
        if result.returncode == 0:
            print_info_verbose(f"Interface {interface_name!r}: removed stale kernel TUN device.")
            return True
        stderr_text = str(result.stderr or "").strip()
        if stderr_text:
            print_info_debug(f"[ligolo] Kernel interface deletion failed for {interface_name}: {stderr_text}")
        return False

    def _interface_has_active_tunnel(self, interface_name: str) -> bool:
        """Return whether one Ligolo agent is actively running on the interface."""

        return any(
            bool(agent.get("running")) and str(agent.get("interface") or "").strip() == interface_name
            for agent in self.list_agents()
        )

    def _cleanup_stale_interface(self, interface_name: str) -> None:
        """Best-effort cleanup for one stale Ligolo interface in API config and kernel."""

        if not interface_name:
            return
        if self._interface_has_active_tunnel(interface_name):
            print_info_debug(f"[ligolo] Refusing stale cleanup for active interface {interface_name!r}.")
            return
        try:
            self._api_request(
                method="DELETE",
                path="/api/v1/interfaces",
                payload={"Interface": interface_name},
            )
            print_info_verbose(f"Interface {interface_name!r}: stale conflict removed via Ligolo API.")
        except RuntimeError as exc:
            print_info_debug(f"[ligolo] Stale interface API cleanup failed for {interface_name!r}: {exc}")
        self._delete_kernel_interface(interface_name)

    def _reconcile_route_conflict(self, *, route: str, interface_name: str, conflict_interface: str | None) -> None:
        """Best-effort cleanup for one route blocked by stale Ligolo state."""

        if conflict_interface and conflict_interface != interface_name:
            try:
                self._api_request(
                    method="DELETE",
                    path="/api/v1/routes",
                    payload={"Interface": conflict_interface, "Route": route},
                )
                print_info_verbose(f"Route {route}: removed from conflicting interface {conflict_interface!r}.")
            except RuntimeError as exc:
                print_info_debug(
                    f"[ligolo] Conflict route cleanup failed for {route} on {conflict_interface!r}: {exc}"
                )
                self._cleanup_stale_interface(conflict_interface)

        for owner_interface in self._list_active_route_interfaces(route):
            if owner_interface == interface_name:
                continue
            if self._interface_has_active_tunnel(owner_interface):
                print_info_debug(
                    f"[ligolo] Route {route} still belongs to active interface {owner_interface!r}; skipping kernel cleanup."
                )
                continue
            self._delete_kernel_route(route=route, interface_name=owner_interface)
            self._cleanup_stale_interface(owner_interface)

    def ensure_interface(self, interface_name: str) -> None:
        """Ensure one interface exists in the Ligolo config/runtime.

        If the interface already exists but has no active tunnel (stale state
        from a previous failed pivot), it is deleted and recreated so that the
        Viper config entry is present — required for route addition to succeed.
        """
        interface_state = self.get_interface_state(interface_name)
        if interface_state is not None:
            # Check whether a tunnel is actively running on this interface.
            has_active_tunnel = self._interface_has_active_tunnel(interface_name)
            if has_active_tunnel:
                print_info_verbose(f"Interface {interface_name!r}: already active, skipping creation.")
                return  # Interface is live — nothing to do.
            # Stale interface (physical TUN exists but no tunnel / not in
            # config).  Delete it so that POST /api/v1/interfaces re-registers
            # it in the Viper config, which is required for route addition.
            print_info_verbose(f"Interface {interface_name!r}: stale (no active tunnel) — deleting and recreating.")
            try:
                self._api_request(
                    method="DELETE",
                    path="/api/v1/interfaces",
                    payload={"Interface": interface_name},
                )
            except RuntimeError:
                pass  # Best-effort cleanup; proceed with creation regardless.
        self._api_request(
            method="POST",
            path="/api/v1/interfaces",
            payload={"Interface": interface_name},
        )
        print_info_verbose(f"Interface {interface_name!r}: created.")

    def ensure_routes(self, *, interface_name: str, routes: list[str]) -> list[str]:
        """Ensure selected routes exist on one interface, returning routes that were newly added.

        Handles two edge-cases:
        - Route already active on another interface (e.g. a stale ligolo_test TUN):
          the conflicting route is deleted from the other interface first.
        - ``file exists`` kernel error: the route is already in the OS routing
          table via an unknown source; treated as success and included in the
          returned list so the caller knows it was requested.
        """
        # Snapshot all interface states to detect cross-interface conflicts.
        all_interfaces = self._api_request(method="GET", path="/api/v1/interfaces")
        if not isinstance(all_interfaces, dict):
            all_interfaces = {}

        # Build route → owning interface map (active routes only).
        route_to_iface: dict[str, str] = {}
        our_active: set[str] = set()
        for iface, istate in all_interfaces.items():
            if not isinstance(istate, dict):
                continue
            for r in (istate.get("Routes") or []):
                if not isinstance(r, dict) or not r.get("Active"):
                    continue
                dst = str(r.get("Destination") or "").strip()
                if not dst:
                    continue
                route_to_iface[dst] = iface
                if iface == interface_name:
                    our_active.add(dst)

        added_routes: list[str] = []
        for route in routes:
            if not route or route in our_active:
                print_info_verbose(f"Route {route}: already active on {interface_name!r}, skipping.")
                continue  # Already active on our interface.

            # Remove the route from any other interface that currently owns it.
            conflict = route_to_iface.get(route)
            if conflict and conflict != interface_name:
                print_info_verbose(f"Route {route}: conflicts with interface {conflict!r} — removing conflict first.")
                self._reconcile_route_conflict(
                    route=route,
                    interface_name=interface_name,
                    conflict_interface=conflict,
                )

            # Add the route to our interface.
            try:
                self._api_request(
                    method="POST",
                    path="/api/v1/routes",
                    payload={"Interface": interface_name, "Route": [route]},
                )
            except RuntimeError as exc:
                if "file exists" in str(exc).lower():
                    print_info_verbose(
                        f"Route {route}: kernel conflict detected during add; reconciling stale state and retrying."
                    )
                    self._reconcile_route_conflict(
                        route=route,
                        interface_name=interface_name,
                        conflict_interface=conflict,
                    )
                    self._api_request(
                        method="POST",
                        path="/api/v1/routes",
                        payload={"Interface": interface_name, "Route": [route]},
                    )
                else:
                    raise
            print_info_verbose(f"Route {route} → {interface_name!r}: added.")
            added_routes.append(route)

        return added_routes

    def ensure_tunnel_started(
        self,
        *,
        agent_id: int,
        interface_name: str,
        timeout_seconds: float = 90.0,
    ) -> None:
        """Ensure one Ligolo tunnel is running for the selected agent and interface.

        Issues a POST to start the tunnel then polls until ``Running`` is True.
        The Ligolo API is asynchronous — the POST returns immediately with a
        "tunnel starting" acknowledgement; the tunnel may not be active yet.

        Handles transient agent reconnects: if the agent drops and reconnects
        under a new numeric ID (same name), the start request is re-issued for
        the new ID automatically.
        """
        agents = self.list_agents()
        agent = next((a for a in agents if int(a.get("id", -1)) == agent_id), None)
        if agent and bool(agent.get("running")) and str(agent.get("interface") or "").strip() == interface_name:
            print_info_verbose(f"Tunnel already running on interface {interface_name!r} for agent {agent_id}.")
            return

        agent_name = str(agent.get("name") or "").strip() if agent else ""

        print_info_verbose(f"Starting tunnel: agent {agent_id} → interface {interface_name!r}…")
        self._api_request(
            method="POST",
            path=f"/api/v1/tunnel/{agent_id}",
            payload={"Interface": interface_name},
        )
        print_info_debug(f"POST /api/v1/tunnel/{agent_id} accepted; polling for Running=True (timeout {timeout_seconds:.0f}s)…")

        deadline = time.time() + timeout_seconds
        current_agent_id = agent_id
        last_issued_id = agent_id
        while time.time() < deadline:
            time.sleep(2.0)
            try:
                agents = self.list_agents()
            except RuntimeError:
                continue

            # Check whether the current agent_id has the tunnel running.
            for a in agents:
                if int(a.get("id", -1)) == current_agent_id:
                    if bool(a.get("running")) and str(a.get("interface") or "").strip() == interface_name:
                        print_info_verbose(
                            f"Tunnel active: agent {current_agent_id} is Running=True on interface {interface_name!r}."
                        )
                        return
                    print_info_debug(
                        f"Agent {current_agent_id} still Running=False on {a.get('interface')!r}; waiting…"
                    )
                    break

            # Agent may have dropped and reconnected under a new numeric ID
            # (same agent name).  Re-issue the tunnel start for the new ID.
            if agent_name:
                for a in agents:
                    new_id = int(a.get("id", -1))
                    if str(a.get("name") or "").strip() == agent_name and new_id != last_issued_id:
                        print_info_verbose(
                            f"Agent reconnected as id={new_id} (was {last_issued_id}); re-issuing tunnel start."
                        )
                        try:
                            self._api_request(
                                method="POST",
                                path=f"/api/v1/tunnel/{new_id}",
                                payload={"Interface": interface_name},
                            )
                        except RuntimeError:
                            pass
                        current_agent_id = new_id
                        last_issued_id = new_id
                        break

        raise RuntimeError(
            f"Ligolo tunnel on interface '{interface_name}' did not reach Running state "
            f"within {timeout_seconds:.0f}s."
        )

    def stop_proxy(self) -> dict[str, Any]:
        """Stop the workspace-scoped Ligolo proxy if it is running."""

        state = self.load_state()
        if not state:
            raise RuntimeError("no ligolo-ng proxy state exists for this workspace")

        pid = state.get("pid")
        if not _is_pid_running(pid):
            state["status"] = "stopped"
            state["updated_at"] = _utc_now_iso()
            self.save_state(state)
            return state

        started_at = time.perf_counter()
        try:
            os.killpg(int(pid), signal.SIGTERM)
        except Exception:
            os.kill(int(pid), signal.SIGTERM)

        deadline = time.time() + _LIGOLO_STOP_WAIT_SECONDS
        while time.time() < deadline:
            if not _is_pid_running(int(pid)):
                break
            time.sleep(0.1)

        if _is_pid_running(int(pid)):
            try:
                os.killpg(int(pid), signal.SIGKILL)
            except Exception:
                os.kill(int(pid), signal.SIGKILL)

        state["status"] = "stopped"
        state["stopped_at"] = _utc_now_iso()
        state["updated_at"] = _utc_now_iso()
        self.save_state(state)
        self._emit_detached_result_debug(
            pid=int(pid),
            elapsed_seconds=max(0.0, time.perf_counter() - started_at),
            returncode=0,
        )
        return state

    def get_status(self) -> dict[str, Any]:
        """Return the current persisted status enriched with runtime liveness."""

        state = self.load_state() or {
            "config_file": str(self.paths.config_file),
            "status": "not_configured",
            "stdout_log": str(self.paths.stdout_log),
            "stderr_log": str(self.paths.stderr_log),
            "workspace_dir": str(self.workspace_dir),
            "current_domain": self.current_domain,
        }
        pid = state.get("pid")
        state["alive"] = _is_pid_running(pid)
        if state.get("status") == "running" and not state["alive"]:
            state["status"] = "stale"
        state["updated_at"] = _utc_now_iso()
        return state

    def read_recent_logs(self, *, max_lines: int = 20) -> dict[str, list[str]]:
        """Return recent stdout/stderr log lines for user-facing diagnostics."""

        stdout_head, stdout_tail, _ = _read_log_lines_preview(
            self.paths.stdout_log,
            head=max_lines,
            tail=max_lines,
        )
        stderr_head, stderr_tail, _ = _read_log_lines_preview(
            self.paths.stderr_log,
            head=max_lines,
            tail=max_lines,
        )
        stdout_lines = stdout_tail or stdout_head
        stderr_lines = stderr_tail or stderr_head
        return {"stdout": stdout_lines, "stderr": stderr_lines}

    def build_debug_log_preview(self) -> str:
        """Return an ADscan-style stdout/stderr preview from persisted log files."""

        return _build_detached_process_preview(self.paths.stdout_log, self.paths.stderr_log)


__all__ = [
    "DEFAULT_LIGOLO_PROXY_API_ADDR",
    "DEFAULT_LIGOLO_PROXY_LISTEN_ADDR",
    "DEFAULT_LIGOLO_PROXY_LISTEN_CANDIDATES",
    "LigoloProxyPaths",
    "LigoloProxyService",
]
