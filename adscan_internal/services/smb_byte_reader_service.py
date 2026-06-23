"""Read SMB remote files in-memory with aiosmb for AI analysis flows."""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
import threading
from dataclasses import dataclass
from typing import Any

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.smb_guest_auth_service import (
    is_guest_alias,
    resolve_smb_guest_username,
)
from adscan_internal.services.smb_transport import (
    SMBConfig,
    SMBTransportError,
    _looks_like_nt_hash,
    run_smb_operation,
    smb_machine_for,
)

# Per-read chunk for ranged reads. Bounded so a large `length` streams in steady
# SMB reads rather than one giant request; sized for VPN-latency budgets (§ 7bis
# adscan-ad-constraints) without being chatty.
_RANGED_READ_CHUNK = 1024 * 1024


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


@dataclass(frozen=True)
class _SMBReadContext:
    """Resolved auth + target context shared by byte-stream and ranged reads."""

    config: SMBConfig
    unc_file_path: str
    normalized_path: str
    username: str
    resolved_auth_domain: str
    auth_mode: str
    resolved_domain_key: str
    effective_source_path: str


class SMBByteReaderService(BaseService):
    """Read remote SMB files directly into memory without local download."""

    backend: str = "smb_aiosmb"

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

    def _resolve_read_context(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        effective_source_path: str,
        timeout_seconds: int,
        auth_username: str | None,
        auth_password: str | None,
        auth_domain: str | None,
    ) -> tuple[_SMBReadContext | None, SMBByteReadResult | None]:
        """Resolve credentials + build the SMBConfig/UNC path for one remote read.

        Shared by :meth:`read_file_bytes` (sequential stream) and
        :meth:`read_range` (random-access sparse read) so auth resolution,
        guest/hash detection and path normalisation live in exactly one place.
        Returns ``(context, None)`` on success or ``(None, error_result)`` when the
        credentials or path are unusable.
        """
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
        username = (
            str(auth_username).strip()
            if auth_username is not None
            else str(domain_data.get("username", "")).strip()
        )
        password = (
            str(auth_password).strip()
            if auth_password is not None
            else str(domain_data.get("password", "")).strip()
        )
        domain_auth_mode = str(domain_data.get("auth", "")).strip().lower()
        has_hash_detector = callable(getattr(shell, "is_hash", None))
        is_hash = bool(
            has_hash_detector and shell.is_hash(password)
        ) or _looks_like_nt_hash(password)
        is_guest_context = domain_auth_mode == "guest" or is_guest_alias(username)
        if is_hash:
            auth_mode = "hash"
        elif password:
            auth_mode = "password"
        elif username and is_guest_context:
            auth_mode = "guest"
        else:
            auth_mode = "missing"

        if auth_mode == "guest" and (not username or is_guest_alias(username)):
            username = resolve_smb_guest_username(shell=shell, domain=domain)

        self.logger.debug(
            (
                "SMB read auth context: requested_domain=%s active_domain=%s "
                "resolved_domain=%s username=%s auth_mode=%s has_password=%s host=%s share=%s path=%s "
                "override_user=%s override_domain=%s domain_auth_mode=%s"
            ),
            domain,
            active_domain,
            resolved_auth_domain,
            username,
            auth_mode,
            bool(password),
            host,
            share,
            effective_source_path,
            auth_username is not None,
            auth_domain is not None,
            domain_auth_mode or "-",
        )

        if auth_mode == "missing":
            if username:
                error_message = (
                    "Missing password for non-guest SMB credentials "
                    f"(domain {domain}, user {username})."
                )
            else:
                error_message = f"Missing authenticated credentials for domain {domain}."
            return None, SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message=error_message,
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                source_path=effective_source_path,
            )

        # Normalise path: forward-slash → backslash, no leading backslash.
        normalized_path = effective_source_path.replace("/", "\\").lstrip("\\")
        if not normalized_path:
            return None, SMBByteReadResult(
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

        config = SMBConfig(
            target_ip=host,
            target_hostname=host,
            domain=domain or resolved_domain_key or active_domain or None,
            username=username or None,
            password=password if auth_mode == "password" else None,
            nt_hash=password if auth_mode == "hash" else None,
            auth_domain=resolved_auth_domain or None,
            timeout=timeout_seconds,
        )
        context = _SMBReadContext(
            config=config,
            unc_file_path=f"\\{share}\\{normalized_path}",
            normalized_path=normalized_path,
            username=username,
            resolved_auth_domain=resolved_auth_domain,
            auth_mode=auth_mode,
            resolved_domain_key=resolved_domain_key,
            effective_source_path=effective_source_path,
        )
        return context, None

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
        """Read one remote SMB file by byte stream through aiosmb."""
        effective_source_path = str(source_path or remote_path or "").strip()
        if max_bytes <= 0:
            return SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message="max_bytes must be positive.",
                source_path=effective_source_path,
            )

        ctx, error = self._resolve_read_context(
            shell=shell,
            domain=domain,
            host=host,
            share=share,
            effective_source_path=effective_source_path,
            timeout_seconds=timeout_seconds,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_domain=auth_domain,
        )
        if error is not None:
            return error
        assert ctx is not None  # noqa: S101 - error branch returns above

        chunks = bytearray()
        truncated = False

        async def _read_file() -> None:
            nonlocal truncated
            try:
                from aiosmb.commons.interfaces.file import SMBFile
            except ImportError as exc:
                raise SMBTransportError(f"aiosmb is not available: {exc}") from exc

            async with smb_machine_for(ctx.config) as machine:
                file_obj = SMBFile.from_remotepath(machine.connection, ctx.unc_file_path)
                # aiosmb ≤0.4.14 raises bare StopIteration inside async generators
                # at EOF; Python 3.7+ converts that to RuntimeError. Catch it here
                # so callers see a clean end-of-stream rather than a spurious error.
                try:
                    async for chunk, err in machine.get_file_data(file_obj):
                        if err is not None:
                            raise SMBTransportError(str(err))
                        if not chunk:
                            continue
                        remaining = max_bytes - len(chunks)
                        if remaining <= 0:
                            truncated = True
                            return
                        if len(chunk) > remaining:
                            chunks.extend(chunk[:remaining])
                            truncated = True
                            return
                        chunks.extend(chunk)
                except RuntimeError as exc:
                    if not (exc.__cause__ and isinstance(exc.__cause__, StopIteration)):
                        raise

        try:
            run_smb_operation(_read_file())
            return SMBByteReadResult(
                success=True,
                data=bytes(chunks),
                truncated=truncated,
                auth_username=ctx.username,
                auth_domain=ctx.resolved_auth_domain,
                auth_mode=ctx.auth_mode,
                resolved_domain_key=ctx.resolved_domain_key,
                normalized_path=ctx.normalized_path,
                source_path=ctx.effective_source_path,
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
                ctx.normalized_path,
                ctx.username,
                ctx.resolved_auth_domain,
                ctx.auth_mode,
                status_code or "-",
            )
            return SMBByteReadResult(
                success=False,
                data=bytes(chunks),
                truncated=truncated,
                error_message=error_text,
                auth_username=ctx.username,
                auth_domain=ctx.resolved_auth_domain,
                auth_mode=ctx.auth_mode,
                resolved_domain_key=ctx.resolved_domain_key,
                normalized_path=ctx.normalized_path,
                status_code=status_code,
                source_path=ctx.effective_source_path,
            )

    def read_range(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        offset: int,
        length: int,
        source_path: str | None = None,
        remote_path: str | None = None,
        timeout_seconds: int = 30,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> SMBByteReadResult:
        """Read exactly ``length`` bytes starting at ``offset`` from a remote file.

        Random-access ranged read built on aiosmb ``SMBFile.seek`` + ``read`` — the
        enabling primitive for sparse reading of a multi-GB disk image over SMB
        without downloading it whole. ``truncated`` is True when EOF was hit before
        ``length`` bytes were returned. One connection per call; the persistent-
        connection adapter that issues many ranged reads over a single session is a
        separate transport layer that composes this primitive.
        """
        effective_source_path = str(source_path or remote_path or "").strip()
        if offset < 0 or length <= 0:
            return SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message="offset must be >= 0 and length must be > 0.",
                source_path=effective_source_path,
            )

        ctx, error = self._resolve_read_context(
            shell=shell,
            domain=domain,
            host=host,
            share=share,
            effective_source_path=effective_source_path,
            timeout_seconds=timeout_seconds,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_domain=auth_domain,
        )
        if error is not None:
            return error
        assert ctx is not None  # noqa: S101 - error branch returns above

        chunks = bytearray()
        truncated = False

        async def _read_range() -> None:
            nonlocal truncated
            try:
                from aiosmb.commons.interfaces.file import SMBFile
            except ImportError as exc:
                raise SMBTransportError(f"aiosmb is not available: {exc}") from exc

            async with smb_machine_for(ctx.config) as machine:
                file_obj = SMBFile.from_remotepath(machine.connection, ctx.unc_file_path)
                await file_obj.open(machine.connection, "r")
                try:
                    if offset:
                        _, seek_err = await file_obj.seek(offset, 0)
                        if seek_err is not None:
                            raise SMBTransportError(str(seek_err))
                    remaining = length
                    while remaining > 0:
                        data, read_err = await file_obj.read(
                            min(remaining, _RANGED_READ_CHUNK)
                        )
                        if read_err is not None:
                            raise SMBTransportError(str(read_err))
                        if not data:
                            truncated = True
                            return
                        chunks.extend(data)
                        remaining -= len(data)
                finally:
                    try:
                        await file_obj.close()
                    except Exception:  # noqa: BLE001 - best-effort handle close
                        pass

        try:
            run_smb_operation(_read_range())
            return SMBByteReadResult(
                success=True,
                data=bytes(chunks),
                truncated=truncated,
                auth_username=ctx.username,
                auth_domain=ctx.resolved_auth_domain,
                auth_mode=ctx.auth_mode,
                resolved_domain_key=ctx.resolved_domain_key,
                normalized_path=ctx.normalized_path,
                source_path=ctx.effective_source_path,
            )
        except Exception as exc:  # noqa: BLE001
            error_text = str(exc)
            status_code = self._extract_status_code(error_text)
            self.logger.exception(
                (
                    "SMB ranged read failed for host=%s share=%s path=%s offset=%s length=%s "
                    "auth_user=%s auth_mode=%s status=%s"
                ),
                host,
                share,
                ctx.normalized_path,
                offset,
                length,
                ctx.username,
                ctx.auth_mode,
                status_code or "-",
            )
            return SMBByteReadResult(
                success=False,
                data=bytes(chunks),
                truncated=truncated,
                error_message=error_text,
                auth_username=ctx.username,
                auth_domain=ctx.resolved_auth_domain,
                auth_mode=ctx.auth_mode,
                resolved_domain_key=ctx.resolved_domain_key,
                normalized_path=ctx.normalized_path,
                status_code=status_code,
                source_path=ctx.effective_source_path,
            )

    def get_remote_file_size(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str,
        timeout_seconds: int = 15,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> int | None:
        """Return the exact byte size of a remote SMB file (single aiosmb open).

        Used to obtain the precise length a sparse disk reader needs for SEEK_END,
        since share-map metadata stores only a human-formatted size. Returns
        ``None`` when the file cannot be opened.
        """
        ctx, error = self._resolve_read_context(
            shell=shell,
            domain=domain,
            host=host,
            share=share,
            effective_source_path=str(source_path or "").strip(),
            timeout_seconds=timeout_seconds,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_domain=auth_domain,
        )
        if error is not None or ctx is None:
            return None

        size_box: dict[str, int] = {}

        async def _stat() -> None:
            try:
                from aiosmb.commons.interfaces.file import SMBFile
            except ImportError as exc:
                raise SMBTransportError(f"aiosmb is not available: {exc}") from exc
            async with smb_machine_for(ctx.config) as machine:
                file_obj = SMBFile.from_remotepath(machine.connection, ctx.unc_file_path)
                await file_obj.open(machine.connection, "r")
                try:
                    size_box["size"] = int(getattr(file_obj, "size", 0) or 0)
                finally:
                    try:
                        await file_obj.close()
                    except Exception:  # noqa: BLE001 - best-effort handle close
                        pass

        try:
            run_smb_operation(_stat())
        except Exception as exc:  # noqa: BLE001 - size probe failure is non-fatal
            self.logger.debug(
                "SMB file size probe failed for host=%s share=%s path=%s: %s",
                host,
                share,
                ctx.normalized_path,
                exc,
            )
            return None
        return size_box.get("size")

    def list_share_directory(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        dir_path: str = "",
        timeout_seconds: int = 30,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> list[tuple[str, int]]:
        """List ``(name, size)`` of files directly under a share directory.

        Used to discover the sibling files of a snapshot/differencing disk chain
        (the parent ``.vhdx`` of an ``.avhdx`` checkpoint, the extents of a split
        ``.vmdk``) so the chain can be reconstructed. Returns ``[]`` on failure.
        """
        ctx, error = self._resolve_read_context(
            shell=shell,
            domain=domain,
            host=host,
            share=share,
            effective_source_path=str(dir_path or "").strip(),
            timeout_seconds=timeout_seconds,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_domain=auth_domain,
        )
        if error is not None or ctx is None:
            return []

        files: list[tuple[str, int]] = []

        async def _list() -> None:
            from aiosmb.commons.interfaces.directory import SMBDirectory

            async with smb_machine_for(ctx.config) as machine:
                directory = SMBDirectory.from_remotepath(machine.connection, ctx.unc_file_path)
                result = await directory.list(machine.connection)
                if isinstance(result, tuple) and result[1] is not None:
                    raise SMBTransportError(str(result[1]))
                for name, file_obj in (getattr(directory, "files", None) or {}).items():
                    files.append((str(name), int(getattr(file_obj, "size", 0) or 0)))

        try:
            run_smb_operation(_list())
        except Exception as exc:  # noqa: BLE001 - listing failure is non-fatal
            self.logger.debug(
                "SMB directory listing failed for host=%s share=%s dir=%s: %s",
                host,
                share,
                dir_path,
                exc,
            )
            return []
        return files

    def download_remote_file(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str,
        dest_path: str,
        timeout_seconds: int = 300,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> bool:
        """Download a remote SMB file fully to ``dest_path`` over ONE session.

        Reuses the persistent ranged reader (single connection) to stream the file
        in chunks — used to fetch the members of a disk chain locally so dissect can
        reconstruct it. Returns ``True`` on success.
        """
        chunk_size = 8 * 1024 * 1024
        try:
            with self.open_persistent_ranged_reader(
                shell=shell,
                domain=domain,
                host=host,
                share=share,
                source_path=source_path,
                timeout_seconds=timeout_seconds,
                auth_username=auth_username,
                auth_password=auth_password,
                auth_domain=auth_domain,
            ) as reader:
                total = int(reader.size or 0)
                with open(dest_path, "wb") as handle:
                    offset = 0
                    while offset < total:
                        chunk = reader.read_range(offset, min(chunk_size, total - offset))
                        if not chunk:
                            break
                        handle.write(chunk)
                        offset += len(chunk)
            return True
        except Exception as exc:  # noqa: BLE001 - download failure is non-fatal
            self.logger.debug(
                "SMB file download failed for host=%s share=%s path=%s: %s",
                host,
                share,
                source_path,
                exc,
            )
            return False

    def open_persistent_ranged_reader(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str,
        timeout_seconds: int = 30,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> "SMBPersistentRangedReader":
        """Open a persistent ranged reader: ONE SMB session for many ranged reads.

        Returns a context manager that holds a single aiosmb connection + file
        handle open on a background event loop and serves all subsequent
        ``read_range(offset, length)`` calls over it — instead of one connect+auth
        per read. This is what a sparse disk parser (dissect) needs: hundreds of
        random reads become ONE session, not hundreds (fixing OPSEC auth-event
        noise, latency, and log spam). The exact file size is captured at open and
        exposed via ``.size``.

        Raises on credential/path resolution failure (so callers can fall back).
        """
        ctx, error = self._resolve_read_context(
            shell=shell,
            domain=domain,
            host=host,
            share=share,
            effective_source_path=str(source_path or "").strip(),
            timeout_seconds=timeout_seconds,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_domain=auth_domain,
        )
        if error is not None or ctx is None:
            raise SMBTransportError(
                (error.error_message if error else None)
                or "Could not resolve SMB credentials for persistent ranged read."
            )
        return SMBPersistentRangedReader(
            config=ctx.config,
            unc_file_path=ctx.unc_file_path,
            timeout_seconds=timeout_seconds,
        )


class SMBPersistentRangedReader:
    """Single persistent aiosmb session serving many synchronous ranged reads.

    dissect parses a disk image synchronously with many random ``read``/``seek``
    calls. Opening a fresh SMB connection per read (the ``read_range`` primitive)
    is correct but triggers one auth per read — noisy on a monitored DC and slow.
    This holds ONE connection + ONE open file handle alive on a dedicated
    background event loop; sync ``read_range`` calls are marshalled to that loop
    via ``run_coroutine_threadsafe`` semantics. Use as a context manager.
    """

    _READ_CHUNK = 1024 * 1024

    def __init__(self, *, config: SMBConfig, unc_file_path: str, timeout_seconds: int) -> None:
        """Configure the reader; the connection opens on ``__enter__``."""
        self._config = config
        self._unc = unc_file_path
        self._timeout = max(1, int(timeout_seconds))
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._request_queue: asyncio.Queue | None = None
        self._ready = threading.Event()
        self._open_error: BaseException | None = None
        self._size: int | None = None

    @property
    def size(self) -> int | None:
        """Exact byte size of the remote file (captured at open)."""
        return self._size

    def __enter__(self) -> "SMBPersistentRangedReader":
        """Start the background loop and open the persistent connection + file."""
        self._thread = threading.Thread(
            target=self._run_loop, name="adscan-smb-ranged-reader", daemon=True
        )
        self._thread.start()
        if not self._ready.wait(self._timeout):
            raise SMBTransportError("Timed out opening persistent SMB connection.")
        if self._open_error is not None:
            raise self._open_error
        return self

    def __exit__(self, *_exc: Any) -> None:
        """Signal the worker to close the connection and stop the loop."""
        loop = self._loop
        queue = self._request_queue
        if loop is not None and queue is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(queue.put_nowait, None)
            except RuntimeError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=self._timeout)

    def read_range(self, offset: int, length: int) -> bytes:
        """Synchronously read ``length`` bytes at ``offset`` over the live session."""
        loop = self._loop
        queue = self._request_queue
        if loop is None or queue is None:
            raise SMBTransportError("Persistent SMB reader is not open.")
        result_future: concurrent.futures.Future = concurrent.futures.Future()
        loop.call_soon_threadsafe(queue.put_nowait, (int(offset), int(length), result_future))
        return result_future.result(timeout=self._timeout)

    def _run_loop(self) -> None:
        """Background thread entry: own loop, run the serving coroutine."""
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve())
        finally:
            try:
                loop.close()
            except Exception:  # noqa: BLE001 - best-effort loop teardown
                pass

    async def _serve(self) -> None:
        """Open one connection + file, then serve queued ranged-read requests."""
        try:
            from aiosmb.commons.interfaces.file import SMBFile
        except ImportError as exc:  # pragma: no cover - aiosmb always present at runtime
            self._open_error = SMBTransportError(f"aiosmb is not available: {exc}")
            self._ready.set()
            return

        self._request_queue = asyncio.Queue()
        try:
            async with smb_machine_for(self._config) as machine:
                file_obj = SMBFile.from_remotepath(machine.connection, self._unc)
                await file_obj.open(machine.connection, "r")
                self._size = int(getattr(file_obj, "size", 0) or 0)
                self._ready.set()
                try:
                    await self._request_loop(file_obj)
                finally:
                    try:
                        await file_obj.close()
                    except Exception:  # noqa: BLE001 - best-effort handle close
                        pass
        except Exception as exc:  # noqa: BLE001 - surface open failures to __enter__
            if not self._ready.is_set():
                self._open_error = exc
                self._ready.set()

    async def _request_loop(self, file_obj: Any) -> None:
        """Serve (offset, length, future) requests serially on the open handle."""
        assert self._request_queue is not None  # noqa: S101 - set before this runs
        while True:
            item = await self._request_queue.get()
            if item is None:  # close sentinel from __exit__
                return
            offset, length, result_future = item
            if result_future.cancelled():
                continue
            try:
                # ALWAYS seek to the absolute offset: requests are random-access
                # served serially, so the handle position left by a prior read is
                # arbitrary. Skipping the seek for offset==0 (the old bug) made an
                # offset-0 read after any non-zero read return bytes from the wrong
                # position — invisible for sequential reads and flat .vhd layouts,
                # but it corrupts dynamic .vhdx/.qcow2 random access (the VHDX
                # container re-reads low offsets after the BAT) → "no volume found".
                _, seek_err = await file_obj.seek(offset, 0)
                if seek_err is not None:
                    raise SMBTransportError(str(seek_err))
                chunks = bytearray()
                remaining = length
                while remaining > 0:
                    data, read_err = await file_obj.read(min(remaining, self._READ_CHUNK))
                    if read_err is not None:
                        raise SMBTransportError(str(read_err))
                    if not data:
                        break
                    chunks.extend(data)
                    remaining -= len(data)
                result_future.set_result(bytes(chunks))
            except Exception as exc:  # noqa: BLE001 - propagate to the waiting caller
                result_future.set_exception(exc)


# ---------------------------------------------------------------------------
# Backward-compatibility alias — removed once all callers are updated
# ---------------------------------------------------------------------------

ImpacketSMBByteReaderService = SMBByteReaderService
