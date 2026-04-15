"""Reusable local HTTP staging helpers for remote artifact transfer.

This service is intentionally small and transport-agnostic: it serves one local
file over an ephemeral HTTP endpoint so remote execution backends can download
the artifact with short commands instead of chunking the file through the
transport itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import functools
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import sys
import threading
from typing import Sequence
from urllib.parse import quote

from adscan_core.local_bind_address import resolve_first_available_bind_addr
from adscan_core.port_diagnostics import is_tcp_bind_address_available, parse_host_port
from adscan_internal import print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_core.linux_capabilities import (
    CAP_NET_BIND_SERVICE_BIT,
    binary_has_capability,
    process_has_capability,
)

DEFAULT_HTTP_STAGING_BIND_CANDIDATES: tuple[str, ...] = (
    "0.0.0.0:443",
    "0.0.0.0:80",
)


@dataclass(frozen=True, slots=True)
class HttpStagedFile:
    """Describe one locally staged file exposed over HTTP."""

    local_path: Path
    bind_addr: str
    advertised_host: str
    url_path: str
    url: str
    file_size: int


class _SingleFileRequestHandler(BaseHTTPRequestHandler):
    """Serve one exact file path and return 404 for every other request."""

    server_version = "ADscanHTTP/1.0"
    protocol_version = "HTTP/1.1"

    def __init__(
        self,
        *args,
        served_path: str,
        local_file: Path,
        **kwargs,
    ) -> None:
        self._served_path = served_path
        self._local_file = local_file
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:  # noqa: N802
        """Serve the staged file when the exact tokenized path is requested."""

        if self.path != self._served_path:
            self.send_error(404)
            return
        try:
            payload = self._local_file.read_bytes()
        except OSError:
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        """Suppress default HTTP request logging; ADscan logs lifecycle separately."""

        return


class SingleFileHttpTransferService:
    """Serve one local file over HTTP until explicitly stopped."""

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._staged_file: HttpStagedFile | None = None

    @staticmethod
    def resolve_default_bind_addr(
        *,
        candidates: Sequence[str] = DEFAULT_HTTP_STAGING_BIND_CANDIDATES,
        excluded_bind_addrs: Sequence[str] = (),
    ) -> str:
        """Return the first available bind address from the candidate list."""

        excluded = {str(item).strip() for item in excluded_bind_addrs if str(item).strip()}

        def _emit_candidate_debug(bind_addr: str, summary: str) -> None:
            print_info_debug(
                "[http-transfer] Default bind candidate unavailable: "
                + str(mark_sensitive(f"{bind_addr} -> {summary}", "detail"))
            )

        selected, conflicts = resolve_first_available_bind_addr(
            candidates=candidates,
            excluded_bind_addrs=excluded_bind_addrs,
            is_bind_addr_available=is_tcp_bind_address_available,
            can_bind_privileged_port=SingleFileHttpTransferService._can_bind_privileged_port,
            privileged_permission_summary=(
                "permission denied (missing CAP_NET_BIND_SERVICE on ADscan/python runtime)"
            ),
            on_candidate_unavailable=_emit_candidate_debug,
        )
        if selected:
            return selected
        conflict_summaries = [f"{item.bind_addr} -> {item.summary}" for item in conflicts]
        tried = ", ".join(
            str(candidate).strip()
            for candidate in candidates
            if str(candidate).strip() and str(candidate).strip() not in excluded
        )
        raise RuntimeError(
            "No default HTTP staging port is available. "
            f"Tried: {tried or 'none'}."
            + (f" Conflicts: {'; '.join(conflict_summaries)}." if conflict_summaries else "")
        )

    @staticmethod
    def _can_bind_privileged_port() -> bool:
        """Return whether the current ADscan runtime can bind privileged ports."""

        return bool(
            process_has_capability(CAP_NET_BIND_SERVICE_BIT)
            or binary_has_capability(sys.executable, "cap_net_bind_service")
        )

    @staticmethod
    def _assert_bind_permissions_for_bind_addr(bind_addr: str) -> None:
        """Fail early when one privileged HTTP staging port cannot be bound."""

        _host, port = parse_host_port(bind_addr)
        if int(port) >= 1024:
            return
        process_has_bind_service = process_has_capability(CAP_NET_BIND_SERVICE_BIT)
        python_has_bind_service = binary_has_capability(sys.executable, "cap_net_bind_service")
        print_info_debug(
            "[http-transfer] Privileged bind diagnostics: "
            f"bind_addr={bind_addr} "
            f"process_cap_net_bind_service={process_has_bind_service} "
            f"python_binary={mark_sensitive(sys.executable, 'path')} "
            f"python_binary_has_cap_net_bind_service={python_has_bind_service}"
        )
        if process_has_bind_service or python_has_bind_service:
            return
        raise RuntimeError(
            "HTTP staging is configured to use a privileged port "
            f"({bind_addr}), but neither the ADscan process nor the Python runtime binary "
            "has CAP_NET_BIND_SERVICE. The Ligolo proxy can still bind privileged ports if its own binary "
            "has that capability, but the embedded Python HTTP server cannot. "
            "Grant CAP_NET_BIND_SERVICE to the container process or Python runtime, or use a custom HTTP staging address >=1024."
        )

    def start(
        self,
        *,
        local_path: str,
        bind_addr: str,
        advertised_host: str,
    ) -> HttpStagedFile:
        """Start serving one file and return the advertised URL metadata."""

        if self._server is not None:
            raise RuntimeError("HTTP transfer service is already running.")

        local_file = Path(local_path).expanduser().resolve()
        if not local_file.is_file():
            raise FileNotFoundError(f"HTTP staging file does not exist: {local_file}")

        bind_host, bind_port = parse_host_port(bind_addr)
        self._assert_bind_permissions_for_bind_addr(bind_addr)
        token = secrets.token_urlsafe(12).rstrip("=")
        served_path = f"/{token}/{quote(local_file.name)}"
        handler = functools.partial(
            _SingleFileRequestHandler,
            served_path=served_path,
            local_file=local_file,
        )
        server = ThreadingHTTPServer((bind_host, bind_port), handler)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.5},
            daemon=True,
            name="adscan-http-transfer",
        )
        thread.start()

        staged_file = HttpStagedFile(
            local_path=local_file,
            bind_addr=bind_addr,
            advertised_host=advertised_host,
            url_path=served_path,
            url=f"http://{advertised_host}:{bind_port}{served_path}",
            file_size=local_file.stat().st_size,
        )
        self._server = server
        self._thread = thread
        self._staged_file = staged_file
        print_info_debug(
            "[http-transfer] started "
            f"bind_addr={mark_sensitive(bind_addr, 'host')} "
            f"url={mark_sensitive(staged_file.url, 'url')} "
            f"file={mark_sensitive(str(local_file), 'path')} "
            f"file_bytes={staged_file.file_size}"
        )
        return staged_file

    def stop(self) -> None:
        """Stop the HTTP server when it is running."""

        if self._server is None:
            return
        staged_file = self._staged_file
        try:
            self._server.shutdown()
            self._server.server_close()
        finally:
            if self._thread is not None:
                self._thread.join(timeout=2.0)
            self._server = None
            self._thread = None
            self._staged_file = None
        if staged_file is not None:
            print_info_debug(
                "[http-transfer] stopped "
                f"url={mark_sensitive(staged_file.url, 'url')}"
            )


__all__ = [
    "DEFAULT_HTTP_STAGING_BIND_CANDIDATES",
    "HttpStagedFile",
    "SingleFileHttpTransferService",
]
