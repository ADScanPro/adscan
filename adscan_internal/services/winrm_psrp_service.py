"""Reusable WinRM/PSRP helpers for command execution and file transfer.

This service centralises the PSRP-backed operations that were previously
implemented ad hoc via ``nxc winrm -X``. The goal is to keep WinRM features
modular and reusable while preserving the legacy NetExec flows as fallbacks.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import os
import re
import subprocess
import tempfile
import time
from typing import Iterable, Any
import zipfile

from adscan_internal import print_info_debug
from adscan_internal.command_runner import (
    build_execution_output_preview,
    build_text_preview,
    summarize_execution_result,
)
from adscan_internal.rich_output import mark_sensitive


class WinRMPSRPError(RuntimeError):
    """Raised when a PSRP-backed WinRM operation fails."""


@dataclass(slots=True)
class WinRMPSRPExecutionResult:
    """Structured result for a PowerShell execution over PSRP."""

    stdout: str
    stderr: str
    had_errors: bool


@dataclass(slots=True)
class WinRMPSRPBatchFetchResult:
    """Structured result for batched WinRM file staging and download."""

    downloaded_files: list[str]
    staged_file_count: int
    skipped_files: list[tuple[str, str]]


@dataclass(frozen=True, slots=True)
class WinRMPSRPAuthSettings:
    """Resolved pypsrp authentication settings for one WinRM connection."""

    auth: str
    username: str | None
    password: str | None
    kerberos_ticket_path: str | None = None
    negotiate_hostname_override: str | None = None
    negotiate_service: str | None = None


@dataclass(frozen=True, slots=True)
class WinRMPSRPCcacheDiagnosticsSummary:
    """Condensed view of a Kerberos ccache for WinRM compatibility decisions."""

    ticket_path: str
    primary_principal: str | None
    server_principals: list[str]
    has_tgt: bool
    service_ticket_only: bool


class WinRMPSRPService:
    """Execute commands and transfer files over WinRM using ``pypsrp``."""

    def __init__(
        self,
        *,
        domain: str,
        host: str,
        username: str,
        password: str,
        auth_mode: str = "auto",
        kerberos_spn_host: str | None = None,
    ) -> None:
        self.domain = domain
        self.host = host
        self.username = username
        self.password = password
        self.auth_mode = str(auth_mode or "auto").strip().lower() or "auto"
        self.kerberos_spn_host = str(kerberos_spn_host or "").strip() or None
        self._client = None
        self._client_auth_settings: WinRMPSRPAuthSettings | None = None

    def _build_full_username(self) -> str:
        """Return the WinRM username in the format expected by PSRP."""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    def _normalize_secret(self) -> str:
        """Normalize a password or bare NT hash for requests-ntlm."""
        secret = self.password
        if secret and re.fullmatch(r"[0-9A-Fa-f]{32}", secret):
            return f"{'0' * 32}:{secret}"
        return secret

    def _looks_like_ccache_path(self) -> bool:
        """Return True when the configured secret points to a Kerberos ccache."""
        return str(self.password or "").strip().lower().endswith(".ccache")

    def _resolve_auth_settings(self) -> WinRMPSRPAuthSettings:
        """Return the effective pypsrp authentication settings."""
        if self.auth_mode not in {"auto", "ntlm", "kerberos", "negotiate"}:
            raise WinRMPSRPError(
                f"Unsupported WinRM auth mode '{self.auth_mode}'. "
                "Expected one of: auto, ntlm, kerberos, negotiate."
            )

        if self.auth_mode == "auto":
            effective_auth = "kerberos" if self._looks_like_ccache_path() else "ntlm"
        else:
            effective_auth = self.auth_mode

        username: str | None = self._build_full_username()
        password: str | None = self._normalize_secret()
        kerberos_ticket_path: str | None = None

        if effective_auth in {"kerberos", "negotiate"}:
            if self._looks_like_ccache_path():
                kerberos_ticket_path = str(self.password).strip()
                password = None
                # When authenticating via ccache the Kerberos principal is
                # already embedded in the ticket.  Passing a DOMAIN\user string
                # causes pyspnego/gssapi to look for that literal string as a
                # Kerberos principal (producing e.g. "garfield.htbadministrator@REALM"),
                # which is never found in the ccache.  Set username=None so
                # pyspnego picks the principal from the ccache automatically.
                username = None
            elif not str(password or "").strip():
                password = None
            if not self._looks_like_ccache_path() and not str(username or "").strip():
                username = None

        return WinRMPSRPAuthSettings(
            auth=effective_auth,
            username=username,
            password=password,
            kerberos_ticket_path=kerberos_ticket_path,
            negotiate_hostname_override=(self.kerberos_spn_host or self.host)
            if effective_auth in {"kerberos", "negotiate"}
            else None,
            negotiate_service="HTTP"
            if effective_auth in {"kerberos", "negotiate"}
            else None,
        )

    @contextmanager
    def _temporary_kerberos_env(self, auth_settings: WinRMPSRPAuthSettings):
        """Temporarily bind ``KRB5CCNAME`` for Kerberos-backed operations."""
        ticket_path = str(auth_settings.kerberos_ticket_path or "").strip()
        if not ticket_path:
            yield
            return

        # Ensure gssapi can locate the ccache by using an absolute path with
        # the FILE: scheme prefix.  Some pyspnego/gssapi builds silently fail
        # to open a bare relative path or a path without the scheme prefix.
        abs_ticket_path = os.path.abspath(ticket_path)
        krb5ccname_value = (
            abs_ticket_path
            if abs_ticket_path.startswith("FILE:")
            else f"FILE:{abs_ticket_path}"
        )
        previous = os.environ.get("KRB5CCNAME")
        os.environ["KRB5CCNAME"] = krb5ccname_value
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = previous

    def _load_client_class(self):
        """Load the ``pypsrp`` client class or raise a PSRP-specific error."""
        try:
            from pypsrp.client import Client  # type: ignore[import]
        except Exception as exc:  # pragma: no cover - import depends on runtime
            raise WinRMPSRPError(
                "pypsrp is not available; unable to use the WinRM PSRP backend."
            ) from exc
        return Client

    @staticmethod
    def _is_matching_credential_not_found_error(exc: BaseException) -> bool:
        """Return True when pyspnego could not match the requested SPN in ccache."""
        lowered = str(exc or "").strip().lower()
        return "matching credential not found" in lowered

    def _log_auth_debug(
        self,
        *,
        auth_settings: WinRMPSRPAuthSettings,
        stage: str,
        note: str | None = None,
    ) -> None:
        """Emit a concise debug line describing the effective Kerberos/NTLM settings."""
        krb5ccname = (
            f"FILE:{os.path.abspath(auth_settings.kerberos_ticket_path)}"
            if auth_settings.kerberos_ticket_path
            else os.environ.get("KRB5CCNAME")
        )
        print_info_debug(
            "[winrm_psrp] auth: "
            f"stage={mark_sensitive(stage, 'text')}, "
            f"host={mark_sensitive(self.host, 'hostname')}, "
            f"auth={mark_sensitive(auth_settings.auth, 'text')}, "
            f"user={mark_sensitive(str(auth_settings.username or 'ccache_principal'), 'user')}, "
            f"service={mark_sensitive(str(auth_settings.negotiate_service or '-'), 'text')}, "
            f"spn_host={mark_sensitive(str(auth_settings.negotiate_hostname_override or self.host), 'hostname')}, "
            f"ccache={mark_sensitive(str(krb5ccname or '-'), 'path')}"
            + (f", note={mark_sensitive(note, 'text')}" if note else "")
        )

    @staticmethod
    def _normalize_ccache_fs_path(ticket_path: str | None) -> str | None:
        """Return one absolute filesystem path for a Kerberos ccache."""
        raw = str(ticket_path or "").strip()
        if not raw:
            return None
        if raw.startswith("FILE:"):
            raw = raw[5:]
        return os.path.abspath(raw)

    def _read_ccache_diagnostics_with_impacket(
        self,
        ticket_path: str,
    ) -> dict[str, Any]:
        """Return best-effort ccache diagnostics using Impacket's parser."""
        try:
            from impacket.krb5.ccache import CCache  # type: ignore[import]
        except Exception as exc:  # pragma: no cover - optional runtime dependency
            return {"parser": "impacket", "available": False, "error": str(exc)}

        try:
            ccache = CCache.loadFile(ticket_path)
            primary_principal = None
            try:
                if getattr(ccache, "principal", None) is not None:
                    primary_principal = str(ccache.principal.prettyPrint())
            except Exception:
                primary_principal = None

            server_principals: list[str] = []
            has_tgt = False
            credentials = getattr(ccache, "credentials", []) or []
            for cred in credentials:
                try:
                    server = str(cred["server"].prettyPrint())
                except Exception:
                    try:
                        server = str(getattr(cred, "server", ""))
                    except Exception:
                        server = ""
                server = server.strip()
                if not server:
                    continue
                server_principals.append(server)
                if server.lower().startswith("krbtgt/"):
                    has_tgt = True

            return {
                "parser": "impacket",
                "available": True,
                "primary_principal": primary_principal,
                "server_principals": server_principals,
                "credential_count": len(server_principals),
                "has_tgt": has_tgt,
            }
        except Exception as exc:  # pragma: no cover - best effort diagnostics
            return {
                "parser": "impacket",
                "available": True,
                "error": str(exc),
            }

    def _read_ccache_diagnostics_with_klist(self, ticket_path: str) -> dict[str, Any]:
        """Return best-effort ccache diagnostics using ``klist -c`` output."""
        try:
            result = subprocess.run(
                ["klist", "-c", ticket_path],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except Exception as exc:  # pragma: no cover - environment specific
            return {"tool": "klist", "available": False, "error": str(exc)}

        output = f"{result.stdout or ''}\n{result.stderr or ''}"
        normalized_lines = [
            line.strip() for line in output.splitlines() if line.strip()
        ]
        default_principal = None
        server_principals: list[str] = []
        for line in normalized_lines:
            if line.lower().startswith("default principal:"):
                default_principal = line.split(":", 1)[1].strip()
                continue
            if "@" not in line:
                continue
            if re.match(r"^\d{2}/\d{2}/\d{2,4}", line):
                parts = re.split(r"\s{2,}", line)
                if parts:
                    candidate = parts[-1].strip()
                    if candidate and "@" in candidate:
                        server_principals.append(candidate)

        return {
            "tool": "klist",
            "available": True,
            "returncode": result.returncode,
            "default_principal": default_principal,
            "server_principals": server_principals,
            "raw_preview": build_text_preview(output, head=8, tail=8),
        }

    def _log_ccache_diagnostics(
        self,
        *,
        auth_settings: WinRMPSRPAuthSettings,
        stage: str,
    ) -> None:
        """Emit best-effort Kerberos ccache diagnostics for WinRM auth debugging."""
        ticket_path = self._normalize_ccache_fs_path(auth_settings.kerberos_ticket_path)
        if not ticket_path:
            return

        impacket_diag = self._read_ccache_diagnostics_with_impacket(ticket_path)
        klist_diag = self._read_ccache_diagnostics_with_klist(ticket_path)

        impacket_servers = (
            impacket_diag.get("server_principals", [])
            if isinstance(impacket_diag, dict)
            else []
        )
        if isinstance(impacket_servers, list):
            impacket_servers = [
                str(item).strip() for item in impacket_servers if str(item).strip()
            ]
        else:
            impacket_servers = []

        klist_servers = (
            klist_diag.get("server_principals", [])
            if isinstance(klist_diag, dict)
            else []
        )
        if isinstance(klist_servers, list):
            klist_servers = [
                str(item).strip() for item in klist_servers if str(item).strip()
            ]
        else:
            klist_servers = []

        lines = [
            f"stage={stage}",
            f"path={ticket_path}",
            f"exists={os.path.exists(ticket_path)}",
            f"size={os.path.getsize(ticket_path) if os.path.exists(ticket_path) else 0}",
        ]
        if isinstance(impacket_diag, dict):
            lines.append(
                "impacket="
                f"available={impacket_diag.get('available')} "
                f"primary={impacket_diag.get('primary_principal') or '-'} "
                f"credentials={impacket_diag.get('credential_count') or 0} "
                f"has_tgt={impacket_diag.get('has_tgt')}"
            )
            if impacket_servers:
                lines.append(
                    "impacket_servers="
                    + ", ".join(impacket_servers[:8])
                    + (" ..." if len(impacket_servers) > 8 else "")
                )
            if impacket_diag.get("error"):
                lines.append(f"impacket_error={impacket_diag.get('error')}")
        if isinstance(klist_diag, dict):
            lines.append(
                "klist="
                f"available={klist_diag.get('available')} "
                f"rc={klist_diag.get('returncode')} "
                f"default={klist_diag.get('default_principal') or '-'}"
            )
            if klist_servers:
                lines.append(
                    "klist_servers="
                    + ", ".join(klist_servers[:8])
                    + (" ..." if len(klist_servers) > 8 else "")
                )
            if klist_diag.get("error"):
                lines.append(f"klist_error={klist_diag.get('error')}")
            elif klist_diag.get("raw_preview"):
                lines.append(f"klist_preview={klist_diag.get('raw_preview')}")

        print_info_debug(
            "[winrm_psrp] ccache diagnostics:\n"
            + mark_sensitive("\n".join(lines), "text"),
            panel=True,
        )

    def _summarize_ccache_diagnostics(
        self,
        auth_settings: WinRMPSRPAuthSettings,
    ) -> WinRMPSRPCcacheDiagnosticsSummary | None:
        """Return a condensed ccache view for WinRM compatibility decisions."""
        ticket_path = self._normalize_ccache_fs_path(auth_settings.kerberos_ticket_path)
        if not ticket_path:
            return None

        impacket_diag = self._read_ccache_diagnostics_with_impacket(ticket_path)
        klist_diag = self._read_ccache_diagnostics_with_klist(ticket_path)

        primary_principal = None
        server_principals: list[str] = []
        has_tgt = False

        if isinstance(impacket_diag, dict):
            primary_principal = (
                str(impacket_diag.get("primary_principal") or "").strip() or None
            )
            raw_servers = impacket_diag.get("server_principals", [])
            if isinstance(raw_servers, list):
                server_principals = [
                    str(item).strip() for item in raw_servers if str(item).strip()
                ]
            has_tgt = bool(impacket_diag.get("has_tgt"))

        if not primary_principal and isinstance(klist_diag, dict):
            primary_principal = (
                str(klist_diag.get("default_principal") or "").strip() or None
            )
        if not server_principals and isinstance(klist_diag, dict):
            raw_servers = klist_diag.get("server_principals", [])
            if isinstance(raw_servers, list):
                server_principals = [
                    str(item).strip() for item in raw_servers if str(item).strip()
                ]
        if not has_tgt:
            has_tgt = any(
                item.lower().startswith("krbtgt/") for item in server_principals
            )

        service_ticket_only = bool(server_principals) and not has_tgt
        return WinRMPSRPCcacheDiagnosticsSummary(
            ticket_path=ticket_path,
            primary_principal=primary_principal,
            server_principals=server_principals,
            has_tgt=has_tgt,
            service_ticket_only=service_ticket_only,
        )

    def _ensure_ccache_is_psrp_compatible(
        self,
        auth_settings: WinRMPSRPAuthSettings,
        *,
        operation_name: str,
    ) -> None:
        """Reject ccache layouts that pypsrp/pyspnego cannot usually consume."""
        summary = self._summarize_ccache_diagnostics(auth_settings)
        if summary is None or not summary.service_ticket_only:
            return

        service_preview = ", ".join(summary.server_principals[:4])
        if len(summary.server_principals) > 4:
            service_preview += ", ..."
        print_info_debug(
            "[winrm_psrp] service-ticket-only ccache detected: "
            f"operation={mark_sensitive(operation_name, 'text')}, "
            f"host={mark_sensitive(self.host, 'hostname')}, "
            f"principal={mark_sensitive(str(summary.primary_principal or '-'), 'user')}, "
            f"services={mark_sensitive(service_preview or '-', 'text')}, "
            f"has_tgt={summary.has_tgt}. "
            "This ccache contains delegated service tickets but no krbtgt/TGT; "
            "pypsrp/pyspnego on Linux often cannot start WinRM sessions from "
            "service-ticket-only caches."
        )
        raise WinRMPSRPError(
            "WinRM PSRP cannot use this Kerberos ccache because it only contains "
            "service tickets and no krbtgt/TGT. This commonly happens with RBCD "
            "HTTP service tickets generated by getST.py; SMB/Impacket may still "
            "work, but pypsrp/pyspnego usually requires a TGT-backed cache."
        )

    def _build_client(self, auth_settings: WinRMPSRPAuthSettings):
        """Construct one pypsrp client for the supplied auth settings."""
        client_class = self._load_client_class()
        client_kwargs: dict[str, object] = {
            "ssl": False,
            "port": 5985,
            "auth": auth_settings.auth,
        }
        if auth_settings.username is not None:
            client_kwargs["username"] = auth_settings.username
        if auth_settings.password is not None:
            client_kwargs["password"] = auth_settings.password
        if auth_settings.negotiate_hostname_override:
            client_kwargs["negotiate_hostname_override"] = (
                auth_settings.negotiate_hostname_override
            )
        if auth_settings.negotiate_service:
            client_kwargs["negotiate_service"] = auth_settings.negotiate_service

        self._log_auth_debug(auth_settings=auth_settings, stage="client_init")
        self._log_ccache_diagnostics(auth_settings=auth_settings, stage="client_init")
        with self._temporary_kerberos_env(auth_settings):
            return client_class(self.host, **client_kwargs)

    def _get_client(self, auth_settings: WinRMPSRPAuthSettings | None = None):
        """Return a cached PSRP client instance for the supplied auth settings."""
        effective_auth = auth_settings or self._resolve_auth_settings()
        if self._client is not None and self._client_auth_settings is None:
            return self._client
        if self._client is None or self._client_auth_settings != effective_auth:
            try:
                self._client = self._build_client(effective_auth)
                self._client_auth_settings = effective_auth
            except Exception as exc:  # pragma: no cover - network/runtime specific
                raise WinRMPSRPError(
                    f"Failed to initialise WinRM PSRP client for {self.host}: {exc}"
                ) from exc
        return self._client

    def _retry_auth_settings_with_wsmam_fallback(
        self,
        auth_settings: WinRMPSRPAuthSettings,
    ) -> WinRMPSRPAuthSettings | None:
        """Return alternate auth settings for the rare WSMAN SPN fallback path."""
        if auth_settings.auth not in {"kerberos", "negotiate"}:
            return None
        if str(auth_settings.negotiate_service or "").upper() == "WSMAN":
            return None
        return WinRMPSRPAuthSettings(
            auth=auth_settings.auth,
            username=auth_settings.username,
            password=auth_settings.password,
            kerberos_ticket_path=auth_settings.kerberos_ticket_path,
            negotiate_hostname_override=auth_settings.negotiate_hostname_override,
            negotiate_service="WSMAN",
        )

    def _execute_with_kerberos_service_fallback(
        self,
        operation,
        *,
        operation_name: str,
    ):
        """Run one PSRP operation and retry once with WSMAN if ccache/SPN matching fails."""
        auth_settings = self._resolve_auth_settings()
        self._ensure_ccache_is_psrp_compatible(
            auth_settings,
            operation_name=operation_name,
        )
        client = self._get_client(auth_settings)
        try:
            with self._temporary_kerberos_env(auth_settings):
                return operation(client, auth_settings)
        except Exception as exc:
            fallback_auth = self._retry_auth_settings_with_wsmam_fallback(auth_settings)
            if not (
                fallback_auth and self._is_matching_credential_not_found_error(exc)
            ):
                raise
            self._log_auth_debug(
                auth_settings=fallback_auth,
                stage="fallback_retry",
                note=(
                    f"{operation_name} retry after HTTP ticket/SPN mismatch; "
                    "trying WSMAN service class"
                ),
            )
            self._log_ccache_diagnostics(
                auth_settings=fallback_auth,
                stage="fallback_retry",
            )
            self._client = None
            self._client_auth_settings = None
            fallback_client = self._get_client(fallback_auth)
            with self._temporary_kerberos_env(fallback_auth):
                return operation(fallback_client, fallback_auth)

    def _log_execution_debug(
        self,
        *,
        script: str,
        stdout: str,
        stderr: str,
        had_errors: bool,
        duration_seconds: float,
        operation_name: str | None = None,
    ) -> None:
        """Emit one Rich debug summary for a PSRP execution result."""
        try:
            command_preview = build_text_preview(script or "", head=20, tail=20)
            print_info_debug(
                "[winrm_psrp] Command:\n"
                + mark_sensitive(command_preview or script or "", "text"),
                panel=True,
            )
            synthetic_result = subprocess.CompletedProcess(
                args="[winrm_psrp]",
                returncode=1 if had_errors else 0,
                stdout=stdout or "",
                stderr=stderr or "",
            )
            setattr(synthetic_result, "_adscan_elapsed_seconds", duration_seconds)
            exit_code, stdout_count, stderr_count, duration_text = (
                summarize_execution_result(synthetic_result)
            )
            script_hash = hashlib.sha1((script or "").encode("utf-8")).hexdigest()[:12]
            script_lines = len(
                [line for line in (script or "").splitlines() if line.strip()]
            )
            print_info_debug(
                "[winrm_psrp] Result: "
                f"host={mark_sensitive(self.host, 'hostname')}, "
                f"user={mark_sensitive(self.username, 'user')}, "
                f"operation={mark_sensitive(operation_name or 'winrm_powershell', 'text')}, "
                f"script_sha1={script_hash}, "
                f"script_lines={script_lines}, "
                f"exit_code={exit_code}, "
                f"stdout_lines={stdout_count}, "
                f"stderr_lines={stderr_count}, "
                f"had_errors={had_errors}, "
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
                    "[winrm_psrp] Output preview:\n"
                    + mark_sensitive(preview_text, "text"),
                    panel=True,
                )
        except Exception:
            return

    def execute_powershell(
        self,
        script: str,
        *,
        operation_name: str | None = None,
        require_logon_bypass: bool = False,
    ) -> WinRMPSRPExecutionResult:
        """Execute PowerShell over PSRP and return structured output."""
        _ = require_logon_bypass
        started_at = time.perf_counter()
        try:
            stdout, streams, had_errors = self._execute_with_kerberos_service_fallback(
                lambda client, _auth_settings: client.execute_ps(script),
                operation_name=operation_name or "winrm_powershell",
            )
        except Exception as exc:  # pragma: no cover - network/runtime specific
            raise WinRMPSRPError(
                f"WinRM PSRP PowerShell execution failed on {self.host}: {exc}"
            ) from exc
        duration_seconds = time.perf_counter() - started_at

        stderr_parts: list[str] = []
        for stream_name in ("error", "warning", "verbose", "debug"):
            stream = getattr(streams, stream_name, None)
            if not stream:
                continue
            stderr_parts.extend(str(item) for item in stream if str(item).strip())

        stderr_text = "\n".join(stderr_parts).strip()
        self._log_execution_debug(
            script=script,
            stdout=stdout or "",
            stderr=stderr_text,
            had_errors=bool(had_errors),
            duration_seconds=duration_seconds,
            operation_name=operation_name,
        )

        return WinRMPSRPExecutionResult(
            stdout=stdout or "",
            stderr=stderr_text,
            had_errors=bool(had_errors),
        )

    def fetch_files(self, paths: Iterable[str], download_dir: str) -> list[str]:
        """Download remote files to a local directory via PSRP."""
        os.makedirs(download_dir, exist_ok=True)
        downloaded_files: list[str] = []

        for remote_path in paths:
            file_name = remote_path.split("\\")[-1]
            save_path = str(Path(download_dir) / file_name)
            self.fetch_file(remote_path, save_path)
            downloaded_files.append(save_path)

        return downloaded_files

    def fetch_file(self, remote_path: str, save_path: str) -> str:
        """Download one remote file to one explicit local path via PSRP."""
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        try:
            self._execute_with_kerberos_service_fallback(
                lambda client, _auth_settings: client.fetch(remote_path, save_path),
                operation_name="winrm_fetch_file",
            )
        except Exception as exc:  # pragma: no cover - network/runtime specific
            raise WinRMPSRPError(
                f"WinRM PSRP file download failed for {remote_path} on "
                f"{self.host}: {exc}"
            ) from exc
        return save_path

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload one local file to one remote path via PSRP."""
        try:
            from pypsrp.complex_objects import PSInvocationState  # type: ignore[import]
            from pypsrp.powershell import PowerShell, RunspacePool  # type: ignore[import]
        except Exception as exc:  # pragma: no cover - import depends on runtime
            raise WinRMPSRPError(
                "pypsrp PowerShell helpers are not available; unable to upload via PSRP."
            ) from exc

        if not os.path.exists(local_path) or not os.path.isfile(local_path):
            raise WinRMPSRPError(
                f"Local file '{local_path}' does not exist or is not a file."
            )

        file_path = Path(local_path)
        try:
            file_size = file_path.stat().st_size
            with file_path.open("rb") as handle:
                hexdigest = hashlib.md5(handle.read()).hexdigest().upper()
        except OSError as exc:
            raise WinRMPSRPError(
                f"Unable to prepare local file '{local_path}' for WinRM upload: {exc}"
            ) from exc

        send_ps_script = r"""
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Base64Chunk,
    [Parameter(Mandatory=$true, Position=1)]
    [int]$ChunkType = 0,
    [Parameter(Mandatory=$false, Position=2)]
    [string]$TempFilePath,
    [Parameter(Mandatory=$false, Position=3)]
    [string]$FilePath,
    [Parameter(Mandatory=$false, Position=4)]
    [string]$FileHash
)

$fileStream = $null

if ($ChunkType -eq 0 -or $ChunkType -eq 3) {
    $TempFilePath = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        [System.IO.Path]::GetRandomFileName()
    )

    [PSCustomObject]@{
        Type         = "Metadata"
        TempFilePath = $TempFilePath
    } | ConvertTo-Json -Compress | Write-Output
}

try {
    $chunkBytes = [System.Convert]::FromBase64String($Base64Chunk)

    $fileStream = New-Object System.IO.FileStream(
        $TempFilePath,
        [System.IO.FileMode]::Append,
        [System.IO.FileAccess]::Write
    )

    $fileStream.Write($chunkBytes, 0, $chunkBytes.Length)
    $fileStream.Close()
} catch {
    $msg = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
    [PSCustomObject]@{
        Type    = "Error"
        Message = "Error processing chunk or writing to file: $msg"
    } | ConvertTo-Json -Compress | Write-Output
} finally {
    if ($fileStream) {
        $fileStream.Dispose()
    }
}

if ($ChunkType -eq 1 -or $ChunkType -eq 3) {
    try {
        if ($TempFilePath) {
            $calculatedHash = (Get-FileHash -Path $TempFilePath -Algorithm MD5).Hash
            if ($calculatedHash -eq $FileHash) {
                [System.IO.File]::Delete($FilePath)
                [System.IO.File]::Move($TempFilePath, $FilePath)

                $fileInfo = Get-Item -Path $FilePath
                $fileSize = $fileInfo.Length
                $fileHash = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash

                [PSCustomObject]@{
                    Type     = "Metadata"
                    FilePath = $FilePath
                    FileSize = $fileSize
                    FileHash = $fileHash
                    FileName = $fileInfo.Name
                } | ConvertTo-Json -Compress | Write-Output
            } else {
                [PSCustomObject]@{
                    Type    = "Error"
                    Message = "File hash mismatch. Expected: $FileHash, Calculated: $calculatedHash"
                } | ConvertTo-Json -Compress | Write-Output
            }
        } else {
            [PSCustomObject]@{
                Type    = "Error"
                Message = "File hash not provided for verification."
            } | ConvertTo-Json -Compress | Write-Output
        }
    } catch {
        $msg = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
        [PSCustomObject]@{
            Type    = "Error"
            Message = "Error processing chunk or writing to file: $msg"
        } | ConvertTo-Json -Compress | Write-Output
    }
}
"""

        chunk_size = 65536
        total_chunks = (file_size + chunk_size - 1) // chunk_size

        try:

            def _upload_operation(client, _auth_settings):
                with RunspacePool(client.wsman) as pool:
                    temp_file_path = ""
                    metadata: dict | None = None

                    with file_path.open("rb") as src:
                        for index in range(total_chunks):
                            chunk = src.read(chunk_size)
                            if not chunk:
                                break

                            if total_chunks == 1:
                                chunk_type = 3
                            elif index == 0:
                                chunk_type = 0
                            elif index == total_chunks - 1:
                                chunk_type = 1
                            else:
                                chunk_type = 2

                            base64_chunk = base64.b64encode(chunk).decode("utf-8")

                            ps = PowerShell(pool)
                            ps.add_script(send_ps_script)
                            ps.add_parameter("Base64Chunk", base64_chunk)
                            ps.add_parameter("ChunkType", chunk_type)

                            if chunk_type in (1, 2) and temp_file_path:
                                ps.add_parameter("TempFilePath", temp_file_path)

                            if chunk_type in (1, 3):
                                ps.add_parameter("FilePath", remote_path)
                                ps.add_parameter("FileHash", hexdigest)

                            ps.begin_invoke()
                            while ps.state == PSInvocationState.RUNNING:
                                ps.poll_invoke()

                            for line in ps.output:
                                try:
                                    data = json.loads(str(line))
                                except Exception:
                                    continue

                                if data.get("Type") == "Metadata":
                                    metadata = data
                                    if "TempFilePath" in data:
                                        temp_file_path = str(data["TempFilePath"])
                                elif data.get("Type") == "Error":
                                    raise WinRMPSRPError(
                                        str(
                                            data.get("Message")
                                            or "Unknown WinRM upload error."
                                        )
                                    )

                            if ps.had_errors and ps.streams.error:
                                raise WinRMPSRPError(str(ps.streams.error[0]))

                    return bool(metadata and metadata.get("FilePath") == remote_path)

            return bool(
                self._execute_with_kerberos_service_fallback(
                    _upload_operation,
                    operation_name="winrm_upload_file",
                )
            )
        except WinRMPSRPError:
            raise
        except Exception as exc:  # pragma: no cover - runtime specific
            raise WinRMPSRPError(
                f"WinRM upload failed for {remote_path}: {exc}"
            ) from exc

    @staticmethod
    def _escape_ps_single_quoted(value: str) -> str:
        """Escape a string for a single-quoted PowerShell literal."""
        return value.replace("'", "''")

    def _build_archive_stage_script(self, *, files: Iterable[tuple[str, str]]) -> str:
        """Build a PowerShell script that stages selected files into one ZIP."""
        manifest_json = json.dumps(
            [
                {
                    "RemotePath": remote_path,
                    "RelativePath": relative_path.replace("/", "\\"),
                }
                for remote_path, relative_path in files
            ]
        )
        escaped_manifest = self._escape_ps_single_quoted(manifest_json)
        script_lines = [
            "$ErrorActionPreference='Stop'",
            "$guid=[guid]::NewGuid().Guid",
            "$stageRoot=Join-Path $env:TEMP ('adscan_psrp_stage_'+$guid)",
            "$archivePath=Join-Path $env:TEMP ('adscan_psrp_stage_'+$guid+'.zip')",
            "$manifest=@'",
            escaped_manifest,
            "'@ | ConvertFrom-Json",
            "New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null",
            "$staged=@()",
            "$skipped=@()",
            "foreach($item in $manifest){",
            "    try {",
            "        $destination=Join-Path $stageRoot $item.RelativePath",
            "        $destinationDir=Split-Path -Parent $destination",
            "        if($destinationDir){ New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null }",
            "        Copy-Item -LiteralPath $item.RemotePath -Destination $destination -Force -ErrorAction Stop",
            "        $staged += $item.RemotePath",
            "    } catch {",
            "        $skipped += [PSCustomObject]@{",
            "            RemotePath = $item.RemotePath",
            "            Reason = $_.Exception.Message",
            "        }",
            "    }",
            "}",
            "if($staged.Count -gt 0){",
            "    Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $archivePath -Force",
            "}",
            "[PSCustomObject]@{",
            "    ArchivePath = $(if($staged.Count -gt 0){ $archivePath } else { '' })",
            "    StageRoot = $stageRoot",
            "    StagedFileCount = $staged.Count",
            "    Skipped = @($skipped)",
            "} | ConvertTo-Json -Compress -Depth 4",
        ]
        return "\n".join(script_lines)

    @staticmethod
    def _build_archive_cleanup_script(*, archive_path: str, stage_root: str) -> str:
        """Build a PowerShell cleanup script for remote staging artifacts."""

        def _quoted(value: str) -> str:
            return "'" + value.replace("'", "''") + "'"

        return (
            "$ErrorActionPreference='SilentlyContinue';"
            f"Remove-Item -LiteralPath {_quoted(archive_path)} -Force -ErrorAction SilentlyContinue;"
            f"Remove-Item -LiteralPath {_quoted(stage_root)} -Recurse -Force -ErrorAction SilentlyContinue"
        )

    def fetch_files_batched(
        self,
        *,
        files: Iterable[tuple[str, str]],
        download_dir: str,
    ) -> WinRMPSRPBatchFetchResult:
        """Stage selected remote files into one ZIP, fetch it, and extract locally."""
        file_list = [
            (remote_path, relative_path)
            for remote_path, relative_path in files
            if remote_path and relative_path
        ]
        if not file_list:
            return WinRMPSRPBatchFetchResult(
                downloaded_files=[], staged_file_count=0, skipped_files=[]
            )

        os.makedirs(download_dir, exist_ok=True)
        stage_result = self.execute_powershell(
            self._build_archive_stage_script(files=file_list)
        )
        if stage_result.had_errors and not stage_result.stdout.strip():
            raise WinRMPSRPError(
                stage_result.stderr or "WinRM PSRP archive staging failed."
            )

        archive_path = ""
        stage_root = ""
        staged_file_count = 0
        skipped_files: list[tuple[str, str]] = []
        try:
            payload = json.loads(stage_result.stdout.strip())
            archive_path = str(payload.get("ArchivePath") or "").strip()
            stage_root = str(payload.get("StageRoot") or "").strip()
            staged_file_count = int(payload.get("StagedFileCount") or 0)
            skipped_payload = payload.get("Skipped") or []
            if isinstance(skipped_payload, list):
                skipped_files = [
                    (
                        str(item.get("RemotePath") or "").strip(),
                        str(item.get("Reason") or "").strip(),
                    )
                    for item in skipped_payload
                    if isinstance(item, dict)
                    and str(item.get("RemotePath") or "").strip()
                ]
        except (json.JSONDecodeError, AttributeError) as exc:
            raise WinRMPSRPError(
                "WinRM PSRP archive staging returned an invalid response."
            ) from exc

        if not stage_root:
            raise WinRMPSRPError(
                "WinRM PSRP archive staging did not return the remote staging metadata."
            )
        if staged_file_count <= 0 and archive_path:
            staged_file_count = len(file_list)
        if staged_file_count <= 0:
            raise WinRMPSRPError(
                "WinRM PSRP archive staging could not access any of the selected files."
            )

        temp_archive_path = ""
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
                temp_archive_path = handle.name
            self.fetch_file(archive_path, temp_archive_path)
            with zipfile.ZipFile(temp_archive_path, "r") as archive_handle:
                archive_handle.extractall(download_dir)
        except zipfile.BadZipFile as exc:
            raise WinRMPSRPError(
                f"WinRM PSRP staged archive for {self.host} is not a valid ZIP file: {exc}"
            ) from exc
        finally:
            try:
                self.execute_powershell(
                    self._build_archive_cleanup_script(
                        archive_path=archive_path,
                        stage_root=stage_root,
                    )
                )
            except WinRMPSRPError:
                pass
            if temp_archive_path and os.path.exists(temp_archive_path):
                os.remove(temp_archive_path)

        downloaded_files: list[str] = []
        for _remote_path, relative_path in file_list:
            save_path = str(Path(download_dir) / relative_path)
            if os.path.exists(save_path):
                downloaded_files.append(save_path)
        return WinRMPSRPBatchFetchResult(
            downloaded_files=downloaded_files,
            staged_file_count=staged_file_count,
            skipped_files=skipped_files,
        )
