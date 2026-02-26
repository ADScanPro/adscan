"""Read SMB remote files in-memory with Impacket for AI analysis flows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import re

from adscan_internal.services.base_service import BaseService


class _ReadLimitReached(RuntimeError):
    """Internal signal used to stop Impacket stream when byte cap is reached."""


@dataclass(frozen=True)
class SMBByteReadResult:
    """Result of reading one remote SMB file as bytes."""

    success: bool
    data: bytes
    truncated: bool
    error_message: str | None = None
    auth_username: str = ""
    auth_domain: str = ""
    auth_mode: str = ""
    resolved_domain_key: str = ""
    normalized_path: str = ""
    status_code: str | None = None
    source_path: str = ""


class ImpacketSMBByteReaderService(BaseService):
    """Read remote SMB files directly into memory without local download."""

    @staticmethod
    def _resolve_domain_entry(
        *,
        domains_data: dict[str, Any],
        requested_domain: str,
        active_domain: str,
    ) -> tuple[str, dict[str, Any]]:
        """Resolve domain entry using exact then case-insensitive key matching."""
        candidates: list[str] = []
        for candidate in (requested_domain, active_domain):
            value = str(candidate or "").strip()
            if value and value not in candidates:
                candidates.append(value)

        for candidate in candidates:
            entry = domains_data.get(candidate)
            if isinstance(entry, dict):
                return candidate, entry

        lowered_map: dict[str, str] = {}
        for key in domains_data.keys():
            key_text = str(key).strip()
            if key_text:
                lowered_map.setdefault(key_text.lower(), key_text)

        for candidate in candidates:
            match_key = lowered_map.get(candidate.lower())
            if not match_key:
                continue
            entry = domains_data.get(match_key)
            if isinstance(entry, dict):
                return match_key, entry

        return "", {}

    @staticmethod
    def _extract_status_code(error_text: str) -> str | None:
        """Extract a Windows NTSTATUS code from an error string when present."""
        if not error_text:
            return None
        match = re.search(r"0x[0-9a-fA-F]{8}", error_text)
        if match:
            return match.group(0).lower()
        return None

    def read_file_bytes(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str | None = None,
        remote_path: str | None = None,
        max_bytes: int = 262144,
        timeout_seconds: int = 30,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> SMBByteReadResult:
        """Read one remote SMB file by byte stream through Impacket."""
        effective_source_path = str(source_path or remote_path or "").strip()
        if max_bytes <= 0:
            return SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message="max_bytes must be positive.",
                source_path=effective_source_path,
            )

        domains_data = (
            shell.domains_data
            if hasattr(shell, "domains_data") and isinstance(shell.domains_data, dict)
            else {}
        )
        active_domain = str(getattr(shell, "domain", "") or "").strip()
        resolved_domain_key, domain_data = self._resolve_domain_entry(
            domains_data=domains_data,
            requested_domain=domain,
            active_domain=active_domain,
        )
        resolved_auth_domain = (
            str(auth_domain or "").strip()
            or resolved_domain_key
            or str(domain or "").strip()
            or active_domain
        )
        username = str(auth_username or "").strip() or str(
            domain_data.get("username", "")
        ).strip()
        password = str(auth_password or "").strip() or str(
            domain_data.get("password", "")
        ).strip()
        auth_mode = (
            "hash"
            if bool(
                callable(getattr(shell, "is_hash", None)) and shell.is_hash(password)
            )
            else "password"
        )

        self.logger.debug(
            (
                "SMB byte read auth context: requested_domain=%s active_domain=%s "
                "resolved_domain=%s username=%s auth_mode=%s host=%s share=%s path=%s max_bytes=%s "
                "override_user=%s override_domain=%s"
            ),
            domain,
            active_domain,
            resolved_auth_domain,
            username,
            auth_mode,
            host,
            share,
            effective_source_path,
            max_bytes,
            bool(str(auth_username or "").strip()),
            bool(str(auth_domain or "").strip()),
        )

        if not username or not password:
            return SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message=f"Missing authenticated credentials for domain {domain}.",
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                source_path=effective_source_path,
            )

        try:
            from impacket.smbconnection import SMBConnection  # type: ignore
        except Exception as exc:  # noqa: BLE001
            self.logger.exception("Failed to import impacket.smbconnection")
            return SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message=f"Impacket is unavailable: {exc}",
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                source_path=effective_source_path,
            )

        normalized_path = effective_source_path.replace("/", "\\")
        # Avoid leading separators that may break some SMB servers.
        normalized_path = normalized_path.lstrip("\\")
        if not normalized_path:
            return SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message="Remote path is empty.",
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                source_path=effective_source_path,
            )

        chunks = bytearray()
        truncated = False
        connection = None

        def _collector(chunk: bytes) -> None:
            nonlocal truncated
            if not chunk:
                return
            remaining = max_bytes - len(chunks)
            if remaining <= 0:
                truncated = True
                raise _ReadLimitReached()
            if len(chunk) > remaining:
                chunks.extend(chunk[:remaining])
                truncated = True
                raise _ReadLimitReached()
            chunks.extend(chunk)

        try:
            connection = SMBConnection(
                remoteName=host,
                remoteHost=host,
                sess_port=445,
                timeout=timeout_seconds,
            )

            is_hash = auth_mode == "hash"
            if is_hash:
                connection.login(
                    user=username,
                    password="",
                    domain=resolved_auth_domain,
                    lmhash="aad3b435b51404eeaad3b435b51404ee",
                    nthash=password,
                )
            else:
                connection.login(
                    user=username,
                    password=password,
                    domain=resolved_auth_domain,
                )

            try:
                connection.getFile(share, normalized_path, _collector)
            except _ReadLimitReached:
                # Expected for capped reads.
                pass

            return SMBByteReadResult(
                success=True,
                data=bytes(chunks),
                truncated=truncated,
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                normalized_path=normalized_path,
                source_path=effective_source_path,
            )
        except Exception as exc:  # noqa: BLE001
            error_text = str(exc)
            status_code = self._extract_status_code(error_text)
            self.logger.exception(
                (
                    "SMB byte stream read failed for host=%s share=%s path=%s "
                    "auth_user=%s auth_domain=%s auth_mode=%s status=%s"
                ),
                host,
                share,
                normalized_path,
                username,
                resolved_auth_domain,
                auth_mode,
                status_code or "-",
            )
            return SMBByteReadResult(
                success=False,
                data=bytes(chunks),
                truncated=truncated,
                error_message=error_text,
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                normalized_path=normalized_path,
                status_code=status_code,
                source_path=effective_source_path,
            )
        finally:
            if connection is not None:
                try:
                    connection.logoff()
                except Exception:  # noqa: BLE001
                    pass
