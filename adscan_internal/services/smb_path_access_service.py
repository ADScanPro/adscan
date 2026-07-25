"""Generic SMB path access checks backed by aiosmb.

This service intentionally stays generic: callers provide the target host,
share name, and directory path they care about. The service supports two
complementary models:

- theoretical ACL analysis against the share security descriptor and the
  directory security descriptor
- an optional active write probe for cases where an operator wants runtime
  validation

The main use-case today is validating whether a principal that can set
``scriptPath`` could also stage the referenced script in ``NETLOGON``. The
implementation is generic enough to support future checks against other shares
and paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from uuid import uuid4
import re

from adscan_internal import (
    print_info_debug,
    print_info_verbose,
    print_success_debug,
    print_warning_debug,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.privileged_group_classifier import normalize_sid
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.smb_transport import (
    SMBConfig,
    SMBAccessDeniedError,
    SMBTransportError,
    smb_machine_for,
    run_smb_operation,
)
from adscan_core.rich_output import print_exception


def _looks_like_ntlm_hash(value: str | None) -> bool:
    """Return whether one credential value resembles an NTLM hash."""
    candidate = str(value or "").strip()
    if not candidate:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
        return True
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", candidate))


def _extract_status_code(exc: Exception) -> str | None:
    """Return an NTSTATUS-like code from an SMB exception when available."""
    # aiosmb exceptions often carry the NTSTATUS in their string representation
    msg = str(exc or "").strip()
    # Look for STATUS_ patterns
    match = re.search(r"STATUS_[A-Z0-9_]+", msg)
    if match:
        return match.group(0)
    # Fallback: return the full message if short enough
    if msg and len(msg) < 120:
        return msg
    return None


def _looks_like_kerberos_auth_failure(
    *,
    status_code: str | None,
    error_message: str | None,
) -> bool:
    """Return whether one SMB error looks like a Kerberos authentication failure."""
    combined = f"{str(status_code or '').strip()} {str(error_message or '').strip()}".upper()
    if not combined.strip():
        return False
    kerberos_markers = (
        "KRB_AP_ERR_TKT_EXPIRED",
        "KRB_AP_ERR",
        "KERBEROS SESSIONERROR",
        "TICKET EXPIRED",
    )
    return any(marker in combined for marker in kerberos_markers)


def _normalize_directory_path(directory_path: str | None) -> str:
    """Normalize one SMB directory path for aiosmb operations."""
    normalized = str(directory_path or "").strip().replace("/", "\\")
    normalized = normalized.strip("\\")
    return normalized


def _coerce_bytes(value: object) -> bytes:
    """Return raw bytes for security-descriptor payloads when possible."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, list):
        try:
            return bytes(int(item) & 0xFF for item in value)
        except Exception:  # noqa: BLE001
            return b""
    try:
        try:
            return bytes(cast(bytes, value))
        except Exception:  # noqa: BLE001
            return b""
    except Exception:  # noqa: BLE001
        return b""


def _candidate_directory_open_paths(directory_path: str) -> tuple[str, ...]:
    """Return path candidates that may address the same directory over SMB."""
    normalized = _normalize_directory_path(directory_path)
    candidates: list[str] = []
    for candidate in (normalized, "", "\\") if not normalized else (normalized, f"\\{normalized}", normalized.rstrip("\\")):
        value = str(candidate or "").strip()
        if value not in candidates:
            candidates.append(value)
    return tuple(candidates)


def _sid_matches_candidates(raw_sid: str, candidate_sids: set[str]) -> bool:
    """Return whether one raw SID string matches the candidate set."""
    normalized = normalize_sid(raw_sid or "")
    if not normalized:
        return False
    return normalized in candidate_sids


def _mask_includes_write(mask_value: int) -> bool:
    """Return whether one access mask contains write/create semantics."""
    write_bits = (
        0x10000000 |  # GENERIC_ALL
        0x40000000 |  # GENERIC_WRITE
        0x00000002 |  # FILE_WRITE_DATA / FILE_ADD_FILE
        0x00000004    # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    )
    return bool(mask_value & write_bits)


def _evaluate_security_descriptor_write(
    *,
    descriptor_bytes: bytes,
    candidate_sids: set[str],
) -> tuple[bool, tuple[str, ...]]:
    """Return whether the descriptor grants write semantics to any candidate SID."""
    if not descriptor_bytes:
        return False, ()
    try:
        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
    except Exception:
        return False, ()

    try:
        descriptor = SECURITY_DESCRIPTOR.from_bytes(descriptor_bytes)
    except Exception:
        return False, ()

    dacl = getattr(descriptor, "Dacl", None)
    if dacl is None:
        return True, ("NULL_DACL",)

    denied_mask = 0
    granted_mask = 0
    matched_sids: list[str] = []
    for ace in getattr(dacl, "aces", []):
        ace_sid_raw = ""
        try:
            ace_sid_raw = str(getattr(ace, "Sid", "") or "")
        except Exception:  # noqa: BLE001
            continue
        ace_sid = normalize_sid(ace_sid_raw or "")
        if not ace_sid or ace_sid not in candidate_sids:
            continue
        matched_sids.append(ace_sid)
        try:
            ace_mask = int(getattr(ace, "Mask", 0) or 0)
        except Exception:  # noqa: BLE001
            continue
        type_name = str(getattr(ace, "AceType", "") or "").upper()
        if "DENIED" in type_name:
            denied_mask |= ace_mask
            granted_mask &= ~ace_mask
            continue
        if "ALLOWED" in type_name:
            granted_mask |= ace_mask & ~denied_mask

    return _mask_includes_write(granted_mask), tuple(dict.fromkeys(matched_sids))


def _sd_object_to_bytes(sd_object: object) -> bytes:
    """Serialize a winacl SECURITY_DESCRIPTOR object back to raw bytes."""
    if sd_object is None:
        return b""
    if isinstance(sd_object, bytes):
        return sd_object
    to_bytes = getattr(sd_object, "to_bytes", None)
    if callable(to_bytes):
        try:
            return bytes(to_bytes())
        except Exception:  # noqa: BLE001
            return b""
    return b""


def _unc_path(host: str, share: str, file_path: str) -> str:
    """Build a UNC path for aiosmb SMBFile/SMBDirectory operations."""
    clean = file_path.strip("\\")
    if clean:
        return f"\\\\{host}\\{share}\\{clean}"
    return f"\\\\{host}\\{share}"


@dataclass(frozen=True, slots=True)
class SMBPathWriteProbeResult:
    """Result of one SMB path write probe."""

    success: bool
    share_name: str
    directory_path: str
    target_host: str
    can_list_directory: bool
    auth_mode: str
    can_write: bool
    probed_file_path: str = ""
    error_message: str | None = None
    status_code: str | None = None
    auth_username: str = ""
    auth_domain: str = ""


@dataclass(frozen=True, slots=True)
class SMBFileUploadResult:
    """Result of uploading one file to an SMB share/path."""

    success: bool
    share_name: str
    directory_path: str
    target_host: str
    can_list_directory: bool
    auth_mode: str
    uploaded_file_path: str = ""
    deleted_after: bool = False
    bytes_written: int = 0
    error_message: str | None = None
    status_code: str | None = None
    auth_username: str = ""
    auth_domain: str = ""


@dataclass(frozen=True, slots=True)
class SMBFileDeleteResult:
    """Result of deleting one file from an SMB share/path."""

    success: bool
    share_name: str
    file_path: str
    target_host: str
    auth_mode: str
    error_message: str | None = None
    status_code: str | None = None
    auth_username: str = ""
    auth_domain: str = ""


@dataclass(frozen=True, slots=True)
class SMBPathSecuritySnapshot:
    """Security descriptor snapshot for one SMB share/path pair."""

    success: bool
    share_name: str
    directory_path: str
    target_host: str
    auth_mode: str
    share_descriptor_readable: bool
    path_descriptor_readable: bool
    share_security_descriptor: bytes = b""
    path_security_descriptor: bytes = b""
    share_backing_path: str = ""
    error_message: str | None = None
    status_code: str | None = None
    auth_username: str = ""
    auth_domain: str = ""


@dataclass(frozen=True, slots=True)
class SMBPathAccessEvaluationResult:
    """Theoretical ACL evaluation result for one SMB share/path principal pair."""

    success: bool
    principal_sid: str
    share_name: str
    directory_path: str
    target_host: str
    auth_mode: str
    share_descriptor_readable: bool
    path_descriptor_readable: bool
    share_allows_write: bool
    path_allows_write: bool
    can_write_path: bool
    matched_share_sids: tuple[str, ...] = ()
    matched_path_sids: tuple[str, ...] = ()
    error_message: str | None = None
    status_code: str | None = None
    auth_username: str = ""
    auth_domain: str = ""


class SMBPathAccessService(BaseService):
    """Perform generic SMB share/path write probes with aiosmb."""

    # ------------------------------------------------------------------
    # Internal async helpers
    # ------------------------------------------------------------------

    async def _async_get_share_security_descriptor(
        self,
        *,
        smb_connection: Any,
        share_name: str,
    ) -> tuple[bytes, str]:
        """Return the share security descriptor bytes and backing path for one SMB share.

        Uses SMBShare.get_security_descriptor() which issues an SMB2 QueryInfo
        (INFO_TYPE_SECURITY) on the share root tree — more reliable than
        hNetrShareGetInfo(502) which returns rpc_x_bad_stub_data on many Windows
        versions when ServerName is NULL.

        Returns (sd_bytes, backing_path).  backing_path is empty because the
        SMB2 SD query does not carry the filesystem path; callers that need the
        backing path should use a separate SRVSVC call.
        """
        from aiosmb.commons.interfaces.share import SMBShare

        share = SMBShare(
            name=share_name,
            fullpath=f"\\\\{smb_connection.target.get_hostname_or_ip()}\\{share_name}",
        )
        sd_object, err = await share.get_security_descriptor(smb_connection)
        if err is not None:
            raise err
        descriptor_bytes = _sd_object_to_bytes(sd_object)
        return descriptor_bytes, ""

    async def _async_get_path_security_descriptor(
        self,
        *,
        smb_connection: Any,
        host: str,
        share_name: str,
        directory_path: str,
    ) -> bytes:
        """Return one directory security descriptor from the target share/path.

        Uses aiosmb SMBDirectory.get_security_descriptor() which returns a
        parsed winacl SECURITY_DESCRIPTOR object; we serialise it back to bytes
        so the caller-side ``_evaluate_security_descriptor_write`` can work
        unchanged.
        """
        from aiosmb.commons.interfaces.directory import SMBDirectory

        last_error: Exception | None = None
        for candidate_path in _candidate_directory_open_paths(directory_path):
            unc = _unc_path(host, share_name, candidate_path)
            try:
                directory = SMBDirectory.from_uncpath(unc)
                sd_object, err = await directory.get_security_descriptor(smb_connection)
                if err is not None:
                    last_error = err
                    continue
                return _sd_object_to_bytes(sd_object)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
        if last_error is not None:
            raise last_error
        return b""

    async def _async_collect_security_snapshot(
        self,
        *,
        host_clean: str,
        share_clean: str,
        directory_clean: str,
        username_clean: str,
        domain_clean: str,
        credential: str,
        auth_mode: str,
        use_kerberos: bool,
        kdc_host: str | None,
        spn_host: str | None,
        timeout_seconds: int,
        marked_host: str,
        marked_share: str,
        marked_directory: str,
        marked_username: str,
        marked_domain: str,
    ) -> SMBPathSecuritySnapshot:
        """Async implementation of collect_security_snapshot."""
        is_hash = _looks_like_ntlm_hash(credential)
        config = SMBConfig(
            target_ip=host_clean,
            target_hostname=spn_host or host_clean,
            domain=domain_clean,
            username=username_clean,
            password=None if is_hash or use_kerberos else credential,
            nt_hash=credential if is_hash else None,
            auth_domain=domain_clean,
            kdc_ip=kdc_host,
            timeout=timeout_seconds,
            use_kerberos=use_kerberos,
        )

        share_descriptor_readable = False
        path_descriptor_readable = False
        share_descriptor = b""
        path_descriptor = b""
        share_backing_path = ""

        try:
            async with smb_machine_for(config) as machine:
                try:
                    share_descriptor, share_backing_path = await self._async_get_share_security_descriptor(
                        smb_connection=machine.connection,
                        share_name=share_clean,
                    )
                    share_descriptor_readable = bool(share_descriptor)
                    if share_descriptor_readable:
                        print_info_verbose(
                            "[smb-path] share security descriptor collected: "
                            f"host={marked_host} share={marked_share}"
                        )
                except Exception as exc:  # noqa: BLE001
                    print_warning_debug(
                        "[smb-path] failed to read share security descriptor: "
                        f"host={marked_host} share={marked_share} "
                        f"status={mark_sensitive(_extract_status_code(exc) or '<unknown>', 'text')} "
                        f"error={mark_sensitive(str(exc), 'text')}"
                    )

                try:
                    path_descriptor = await self._async_get_path_security_descriptor(
                        smb_connection=machine.connection,
                        host=host_clean,
                        share_name=share_clean,
                        directory_path=directory_clean,
                    )
                    path_descriptor_readable = bool(path_descriptor)
                    if path_descriptor_readable:
                        print_info_verbose(
                            "[smb-path] path security descriptor collected: "
                            f"host={marked_host} share={marked_share} path={marked_directory}"
                        )
                except SMBAccessDeniedError as exc:
                    print_warning_debug(
                        "[smb-path] failed to read path security descriptor: "
                        f"host={marked_host} share={marked_share} path={marked_directory} "
                        f"status={mark_sensitive(_extract_status_code(exc) or '<unknown>', 'text')} "
                        f"error={mark_sensitive(str(exc), 'text')}"
                    )
                except Exception as exc:  # noqa: BLE001
                    print_warning_debug(
                        "[smb-path] failed to read path security descriptor: "
                        f"host={marked_host} share={marked_share} path={marked_directory} "
                        f"status={mark_sensitive(_extract_status_code(exc) or '<unknown>', 'text')} "
                        f"error={mark_sensitive(str(exc), 'text')}"
                    )

            success = share_descriptor_readable and path_descriptor_readable
            return SMBPathSecuritySnapshot(
                success=success,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode=auth_mode,
                share_descriptor_readable=share_descriptor_readable,
                path_descriptor_readable=path_descriptor_readable,
                share_security_descriptor=share_descriptor,
                path_security_descriptor=path_descriptor,
                share_backing_path=share_backing_path,
                error_message=None if success else "SMB security descriptor snapshot incomplete.",
                auth_username=username_clean,
                auth_domain=domain_clean,
            )
        except SMBTransportError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning_debug(
                "[smb-path] ACL snapshot collection failed: "
                f"host={marked_host} share={marked_share} path={marked_directory} "
                f"user={marked_username} domain={marked_domain} "
                f"auth_mode={mark_sensitive(auth_mode, 'text')} "
                f"status={mark_sensitive(_extract_status_code(exc) or '<unknown>', 'text')} "
                f"error={mark_sensitive(str(exc), 'text')}"
            )
            return SMBPathSecuritySnapshot(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode=auth_mode,
                share_descriptor_readable=share_descriptor_readable,
                path_descriptor_readable=path_descriptor_readable,
                share_security_descriptor=share_descriptor,
                path_security_descriptor=path_descriptor,
                share_backing_path=share_backing_path,
                error_message=str(exc),
                status_code=_extract_status_code(exc),
                auth_username=username_clean,
                auth_domain=domain_clean,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning_debug(
                "[smb-path] ACL snapshot collection failed: "
                f"host={marked_host} share={marked_share} path={marked_directory} "
                f"user={marked_username} domain={marked_domain} "
                f"auth_mode={mark_sensitive(auth_mode, 'text')} "
                f"status={mark_sensitive(_extract_status_code(exc) or '<unknown>', 'text')} "
                f"error={mark_sensitive(str(exc), 'text')}"
            )
            return SMBPathSecuritySnapshot(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode=auth_mode,
                share_descriptor_readable=share_descriptor_readable,
                path_descriptor_readable=path_descriptor_readable,
                share_security_descriptor=share_descriptor,
                path_security_descriptor=path_descriptor,
                share_backing_path=share_backing_path,
                error_message=str(exc),
                status_code=_extract_status_code(exc),
                auth_username=username_clean,
                auth_domain=domain_clean,
            )

    async def _async_probe_write_access(
        self,
        *,
        host_clean: str,
        share_clean: str,
        directory_clean: str,
        username_clean: str,
        domain_clean: str,
        credential: str,
        auth_mode: str,
        is_hash: bool,
        use_kerberos: bool,
        kdc_host: str | None,
        spn_host: str | None,
        timeout_seconds: int,
        marked_host: str,
        marked_share: str,
        marked_directory: str,
        marked_username: str,
        marked_domain: str,
    ) -> SMBPathWriteProbeResult:
        """Async implementation of probe_write_access."""
        config = SMBConfig(
            target_ip=host_clean,
            target_hostname=spn_host or host_clean,
            domain=domain_clean,
            username=username_clean,
            password=None if is_hash or use_kerberos else credential,
            nt_hash=credential if is_hash else None,
            auth_domain=domain_clean,
            kdc_ip=kdc_host,
            timeout=timeout_seconds,
            use_kerberos=use_kerberos,
        )

        can_list_directory = False
        probe_path = ""

        try:
            async with smb_machine_for(config) as machine:
                connection = machine.connection

                # Directory listing probe
                try:
                    from aiosmb.commons.interfaces.directory import SMBDirectory
                    list_unc = _unc_path(host_clean, share_clean, directory_clean)
                    directory = SMBDirectory.from_uncpath(list_unc)
                    _, err = await directory.open(connection)  # pylint: disable=no-member
                    if err is None:
                        can_list_directory = True
                        await directory.close()  # pylint: disable=no-member
                        print_info_verbose(
                            "[smb-path] directory listing succeeded: "
                            f"host={marked_host} share={marked_share} path={marked_directory}"
                        )
                    else:
                        print_warning_debug(
                            "[smb-path] directory listing was denied but write probe will continue: "
                            f"host={marked_host} share={marked_share} path={marked_directory}"
                        )
                except Exception:  # noqa: BLE001
                    pass

                # Write probe: create a temporary file with FILE_DELETE_ON_CLOSE equivalent.
                # aiosmb opens with FILE_OPEN_IF — we create + write + delete.
                from aiosmb.commons.interfaces.file import SMBFile

                probe_name = f".adscan-write-probe-{uuid4().hex}.tmp"
                probe_path = (
                    f"{directory_clean}\\{probe_name}" if directory_clean else probe_name
                )
                file_unc = _unc_path(host_clean, share_clean, probe_path)
                smbfile = SMBFile.from_uncpath(file_unc)
                _, err = await smbfile.open(connection, mode="w")
                if err is not None:
                    raise err
                try:
                    _, werr = await smbfile.write(b"")
                    if werr is not None:
                        pass  # zero-byte write error is non-fatal
                finally:
                    await smbfile.close()
                # Cleanup — best-effort
                try:
                    await SMBFile.delete_rempath(connection, file_unc)
                except Exception:  # noqa: BLE001
                    pass

            print_success_debug(
                "[smb-path] write probe succeeded: "
                f"host={marked_host} share={marked_share} "
                f"path={mark_sensitive(probe_path, 'path')} "
                f"auth_mode={mark_sensitive(auth_mode, 'text')}"
            )
            return SMBPathWriteProbeResult(
                success=True,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                can_list_directory=can_list_directory,
                auth_mode=auth_mode,
                can_write=True,
                probed_file_path=probe_path,
                auth_username=username_clean,
                auth_domain=domain_clean,
            )
        except SMBTransportError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning_debug(
                "[smb-path] write probe failed: "
                f"host={marked_host} share={marked_share} path={marked_directory} "
                f"user={marked_username} domain={marked_domain} "
                f"auth_mode={mark_sensitive(auth_mode, 'text')} "
                f"status={mark_sensitive(_extract_status_code(exc) or '<unknown>', 'text')} "
                f"error={mark_sensitive(str(exc), 'text')}"
            )
            return SMBPathWriteProbeResult(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                can_list_directory=can_list_directory,
                auth_mode=auth_mode,
                can_write=False,
                probed_file_path=probe_path,
                error_message=str(exc),
                status_code=_extract_status_code(exc),
                auth_username=username_clean,
                auth_domain=domain_clean,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning_debug(
                "[smb-path] write probe failed: "
                f"host={marked_host} share={marked_share} path={marked_directory} "
                f"user={marked_username} domain={marked_domain} "
                f"auth_mode={mark_sensitive(auth_mode, 'text')} "
                f"status={mark_sensitive(_extract_status_code(exc) or '<unknown>', 'text')} "
                f"error={mark_sensitive(str(exc), 'text')}"
            )
            return SMBPathWriteProbeResult(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                can_list_directory=can_list_directory,
                auth_mode=auth_mode,
                can_write=False,
                probed_file_path=probe_path,
                error_message=str(exc),
                status_code=_extract_status_code(exc),
                auth_username=username_clean,
                auth_domain=domain_clean,
            )

    async def _async_upload_file(
        self,
        *,
        host_clean: str,
        share_clean: str,
        directory_clean: str,
        username_clean: str,
        domain_clean: str,
        credential: str,
        auth_mode: str,
        is_hash: bool,
        use_kerberos: bool,
        kdc_host: str | None,
        spn_host: str | None,
        timeout_seconds: int,
        remote_name_clean: str,
        file_contents: bytes,
        delete_after: bool,
        marked_host: str,
        marked_share: str,
        marked_directory: str,
        marked_username: str,
        marked_domain: str,
    ) -> tuple[SMBFileUploadResult, Exception | None]:
        """Async implementation of upload_file (single attempt)."""
        config = SMBConfig(
            target_ip=host_clean,
            target_hostname=spn_host or host_clean,
            domain=domain_clean,
            username=username_clean,
            password=None if is_hash or use_kerberos else credential,
            nt_hash=credential if is_hash else None,
            auth_domain=domain_clean,
            kdc_ip=kdc_host,
            timeout=timeout_seconds,
            use_kerberos=use_kerberos,
        )

        can_list_directory = False
        uploaded_path = ""
        deleted_after_successfully = False

        try:
            async with smb_machine_for(config) as machine:
                connection = machine.connection

                # Directory listing probe
                try:
                    from aiosmb.commons.interfaces.directory import SMBDirectory
                    list_unc = _unc_path(host_clean, share_clean, directory_clean)
                    directory = SMBDirectory.from_uncpath(list_unc)
                    _, err = await directory.open(connection)  # pylint: disable=no-member
                    if err is None:
                        can_list_directory = True
                        await directory.close()  # pylint: disable=no-member
                        print_info_verbose(
                            "[smb-path] directory listing succeeded before upload probe: "
                            f"host={marked_host} share={marked_share} path={marked_directory}"
                        )
                    else:
                        print_warning_debug(
                            "[smb-path] directory listing was denied before file upload; "
                            f"upload will continue: host={marked_host} share={marked_share} "
                            f"path={marked_directory}"
                        )
                except Exception:  # noqa: BLE001
                    pass

                from aiosmb.commons.interfaces.file import SMBFile

                uploaded_path = (
                    f"{directory_clean}\\{remote_name_clean}" if directory_clean else remote_name_clean
                )
                file_unc = _unc_path(host_clean, share_clean, uploaded_path)
                smbfile = SMBFile.from_uncpath(file_unc)
                _, err = await smbfile.open(connection, mode="w")
                if err is not None:
                    raise err
                try:
                    _, werr = await smbfile.write(file_contents)
                    if werr is not None:
                        raise werr
                finally:
                    await smbfile.close()

                if delete_after:
                    try:
                        await SMBFile.delete_rempath(connection, file_unc)
                        deleted_after_successfully = True
                    except Exception as exc:  # noqa: BLE001
                        print_warning_debug(
                            "[smb-path] uploaded file but cleanup failed: "
                            f"host={marked_host} share={marked_share} "
                            f"path={mark_sensitive(uploaded_path, 'path')} "
                            f"error={mark_sensitive(str(exc), 'text')}"
                        )

            print_success_debug(
                "[smb-path] file upload succeeded: "
                f"host={marked_host} share={marked_share} "
                f"path={mark_sensitive(uploaded_path, 'path')} "
                f"delete_after={mark_sensitive(str(delete_after).lower(), 'text')} "
                f"auth_mode={mark_sensitive(auth_mode, 'text')}"
            )
            return (
                SMBFileUploadResult(
                    success=True,
                    target_host=host_clean,
                    share_name=share_clean,
                    directory_path=directory_clean,
                    can_list_directory=can_list_directory,
                    auth_mode=auth_mode,
                    uploaded_file_path=uploaded_path,
                    deleted_after=deleted_after_successfully,
                    bytes_written=len(file_contents),
                    auth_username=username_clean,
                    auth_domain=domain_clean,
                ),
                None,
            )
        except Exception as exc:  # noqa: BLE001
            return (
                SMBFileUploadResult(
                    success=False,
                    target_host=host_clean,
                    share_name=share_clean,
                    directory_path=directory_clean,
                    can_list_directory=can_list_directory,
                    auth_mode=auth_mode,
                    uploaded_file_path=uploaded_path,
                    error_message=str(exc),
                    status_code=_extract_status_code(exc),
                    auth_username=username_clean,
                    auth_domain=domain_clean,
                ),
                exc,
            )

    async def _async_delete_file(
        self,
        *,
        host_clean: str,
        share_clean: str,
        file_path_clean: str,
        username_clean: str,
        domain_clean: str,
        credential: str,
        auth_mode: str,
        is_hash: bool,
        use_kerberos: bool,
        kdc_host: str | None,
        spn_host: str | None,
        timeout_seconds: int,
        marked_host: str,
        marked_share: str,
        marked_file_path: str,
        marked_username: str,
        marked_domain: str,
    ) -> tuple[SMBFileDeleteResult, Exception | None]:
        """Async implementation of delete_file (single attempt)."""
        config = SMBConfig(
            target_ip=host_clean,
            target_hostname=spn_host or host_clean,
            domain=domain_clean,
            username=username_clean,
            password=None if is_hash or use_kerberos else credential,
            nt_hash=credential if is_hash else None,
            auth_domain=domain_clean,
            kdc_ip=kdc_host,
            timeout=timeout_seconds,
            use_kerberos=use_kerberos,
        )

        try:
            async with smb_machine_for(config) as machine:
                connection = machine.connection
                from aiosmb.commons.interfaces.file import SMBFile
                # delete_rempath calls from_remotepath() which prepends the host from the
                # connection; passing a full UNC (\host\share\path) would cause double-host
                # expansion. Pass \share\path so from_remotepath builds the correct UNC.
                share_rel_path = f"\\{share_clean}\\{file_path_clean.lstrip(chr(92))}"
                _, err = await SMBFile.delete_rempath(connection, share_rel_path)
                if err is not None:
                    raise err

            print_success_debug(
                "[smb-path] file delete succeeded: "
                f"host={marked_host} share={marked_share} file={marked_file_path} "
                f"auth_mode={mark_sensitive(auth_mode, 'text')}"
            )
            return (
                SMBFileDeleteResult(
                    success=True,
                    target_host=host_clean,
                    share_name=share_clean,
                    file_path=file_path_clean,
                    auth_mode=auth_mode,
                    auth_username=username_clean,
                    auth_domain=domain_clean,
                ),
                None,
            )
        except Exception as exc:  # noqa: BLE001
            return (
                SMBFileDeleteResult(
                    success=False,
                    target_host=host_clean,
                    share_name=share_clean,
                    file_path=file_path_clean,
                    auth_mode=auth_mode,
                    error_message=str(exc),
                    status_code=_extract_status_code(exc),
                    auth_username=username_clean,
                    auth_domain=domain_clean,
                ),
                exc,
            )

    # ------------------------------------------------------------------
    # Private sync helpers
    # ------------------------------------------------------------------

    def _should_retry_with_ntlm(
        self,
        *,
        use_kerberos: bool,
        credential: str,
        status_code: str | None,
        error_message: str | None,
    ) -> bool:
        """Return whether one failed Kerberos SMB operation should retry with NTLM."""
        if not use_kerberos:
            return False
        if not str(credential or "").strip():
            return False
        return _looks_like_kerberos_auth_failure(
            status_code=status_code,
            error_message=error_message,
        )

    # ------------------------------------------------------------------
    # Public API — all sync, same signatures as before
    # ------------------------------------------------------------------

    def collect_security_snapshot(
        self,
        *,
        target_host: str,
        share_name: str,
        directory_path: str = "",
        username: str,
        password: str | None = None,
        auth_domain: str = "",
        use_kerberos: bool = False,
        kdc_host: str | None = None,
        spn_host: str | None = None,
        timeout_seconds: int = 30,
    ) -> SMBPathSecuritySnapshot:
        """Collect theoretical SMB share/path descriptors for later ACL evaluation."""
        share_clean = str(share_name or "").strip()
        host_clean = str(target_host or "").strip()
        username_clean = str(username or "").strip()
        domain_clean = str(auth_domain or "").strip()
        directory_clean = _normalize_directory_path(directory_path)
        if not host_clean or not share_clean or not username_clean:
            return SMBPathSecuritySnapshot(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode="missing",
                share_descriptor_readable=False,
                path_descriptor_readable=False,
                error_message="Missing host, share, or username for SMB ACL snapshot.",
                auth_username=username_clean,
                auth_domain=domain_clean,
            )

        credential = str(password or "").strip()
        is_hash = _looks_like_ntlm_hash(credential)
        auth_mode = "kerberos" if use_kerberos else ("hash" if is_hash else "password")

        marked_host = mark_sensitive(host_clean, "host")
        marked_share = mark_sensitive(share_clean, "text")
        marked_directory = mark_sensitive(directory_clean or "\\", "path")
        marked_username = mark_sensitive(username_clean, "username")
        marked_domain = mark_sensitive(domain_clean or "<local>", "domain")
        print_info_debug(
            "[smb-path] collecting ACL snapshot: "
            f"host={marked_host} share={marked_share} path={marked_directory} "
            f"user={marked_username} domain={marked_domain} "
            f"auth_mode={mark_sensitive(auth_mode, 'text')}"
        )

        # ASYNC_BOUNDARY: sync callers bridge to async here.
        return run_smb_operation(
            self._async_collect_security_snapshot(
                host_clean=host_clean,
                share_clean=share_clean,
                directory_clean=directory_clean,
                username_clean=username_clean,
                domain_clean=domain_clean,
                credential=credential,
                auth_mode=auth_mode,
                use_kerberos=use_kerberos,
                kdc_host=kdc_host,
                spn_host=spn_host,
                timeout_seconds=timeout_seconds,
                marked_host=marked_host,
                marked_share=marked_share,
                marked_directory=marked_directory,
                marked_username=marked_username,
                marked_domain=marked_domain,
            )
        )

    def evaluate_snapshot_write_access(
        self,
        *,
        snapshot: SMBPathSecuritySnapshot,
        principal_sid: str,
        implied_sids: tuple[str, ...] = (),
    ) -> SMBPathAccessEvaluationResult:
        """Evaluate whether one SID is theoretically allowed to write to one SMB path."""
        normalized_principal_sid = normalize_sid(principal_sid or "") or str(principal_sid or "").strip().upper()
        candidate_sids = {
            sid
            for sid in (
                normalized_principal_sid,
                *(normalize_sid(value or "") or str(value or "").strip().upper() for value in implied_sids),
            )
            if sid
        }
        share_allows_write, matched_share_sids = _evaluate_security_descriptor_write(
            descriptor_bytes=snapshot.share_security_descriptor,
            candidate_sids=candidate_sids,
        )
        path_allows_write, matched_path_sids = _evaluate_security_descriptor_write(
            descriptor_bytes=snapshot.path_security_descriptor,
            candidate_sids=candidate_sids,
        )
        can_write_path = bool(share_allows_write and path_allows_write)
        marked_path = mark_sensitive(snapshot.directory_path or "\\", "path")
        print_info_debug(
            "[smb-path] ACL evaluation: "
            f"host={mark_sensitive(snapshot.target_host, 'host')} "
            f"share={mark_sensitive(snapshot.share_name, 'text')} "
            f"path={marked_path} "
            f"principal_sid={mark_sensitive(normalized_principal_sid, 'text')} "
            f"share_write={mark_sensitive(str(share_allows_write).lower(), 'text')} "
            f"path_write={mark_sensitive(str(path_allows_write).lower(), 'text')}"
        )
        return SMBPathAccessEvaluationResult(
            success=bool(snapshot.success),
            principal_sid=normalized_principal_sid,
            share_name=snapshot.share_name,
            directory_path=snapshot.directory_path,
            target_host=snapshot.target_host,
            auth_mode=snapshot.auth_mode,
            share_descriptor_readable=snapshot.share_descriptor_readable,
            path_descriptor_readable=snapshot.path_descriptor_readable,
            share_allows_write=share_allows_write,
            path_allows_write=path_allows_write,
            can_write_path=can_write_path,
            matched_share_sids=matched_share_sids,
            matched_path_sids=matched_path_sids,
            error_message=snapshot.error_message,
            status_code=snapshot.status_code,
            auth_username=snapshot.auth_username,
            auth_domain=snapshot.auth_domain,
        )

    def probe_write_access(
        self,
        *,
        target_host: str,
        share_name: str,
        directory_path: str = "",
        username: str,
        password: str | None = None,
        auth_domain: str = "",
        use_kerberos: bool = False,
        kdc_host: str | None = None,
        spn_host: str | None = None,
        timeout_seconds: int = 30,
    ) -> SMBPathWriteProbeResult:
        """Probe whether one credential context can create a file in an SMB path."""
        share_clean = str(share_name or "").strip()
        host_clean = str(target_host or "").strip()
        username_clean = str(username or "").strip()
        domain_clean = str(auth_domain or "").strip()
        directory_clean = _normalize_directory_path(directory_path)
        if not host_clean or not share_clean or not username_clean:
            return SMBPathWriteProbeResult(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode="missing",
                can_list_directory=False,
                can_write=False,
                error_message="Missing host, share, or username for SMB path probe.",
                auth_username=username_clean,
                auth_domain=domain_clean,
            )

        credential = str(password or "").strip()
        is_hash = _looks_like_ntlm_hash(credential)
        if use_kerberos:
            auth_mode = "kerberos"
        elif is_hash:
            auth_mode = "hash"
        else:
            auth_mode = "password"

        marked_host = mark_sensitive(host_clean, "host")
        marked_share = mark_sensitive(share_clean, "text")
        marked_directory = mark_sensitive(directory_clean or "\\", "path")
        marked_username = mark_sensitive(username_clean, "username")
        marked_domain = mark_sensitive(domain_clean or "<local>", "domain")
        print_info_debug(
            "[smb-path] starting write probe: "
            f"host={marked_host} share={marked_share} path={marked_directory} "
            f"user={marked_username} domain={marked_domain} "
            f"auth_mode={mark_sensitive(auth_mode, 'text')}"
        )

        # ASYNC_BOUNDARY: sync callers bridge to async here.
        return run_smb_operation(
            self._async_probe_write_access(
                host_clean=host_clean,
                share_clean=share_clean,
                directory_clean=directory_clean,
                username_clean=username_clean,
                domain_clean=domain_clean,
                credential=credential,
                auth_mode=auth_mode,
                is_hash=is_hash,
                use_kerberos=use_kerberos,
                kdc_host=kdc_host,
                spn_host=spn_host,
                timeout_seconds=timeout_seconds,
                marked_host=marked_host,
                marked_share=marked_share,
                marked_directory=marked_directory,
                marked_username=marked_username,
                marked_domain=marked_domain,
            )
        )

    def upload_file(
        self,
        *,
        target_host: str,
        share_name: str,
        directory_path: str = "",
        username: str,
        password: str | None = None,
        auth_domain: str = "",
        file_contents: bytes,
        remote_filename: str,
        delete_after: bool = True,
        use_kerberos: bool = False,
        kdc_host: str | None = None,
        spn_host: str | None = None,
        timeout_seconds: int = 30,
    ) -> SMBFileUploadResult:
        """Upload one file to an SMB path and optionally delete it afterwards."""
        share_clean = str(share_name or "").strip()
        host_clean = str(target_host or "").strip()
        username_clean = str(username or "").strip()
        domain_clean = str(auth_domain or "").strip()
        directory_clean = _normalize_directory_path(directory_path)
        remote_name_clean = str(remote_filename or "").strip().replace("/", "\\").strip("\\")
        if not host_clean or not share_clean or not username_clean:
            return SMBFileUploadResult(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode="missing",
                can_list_directory=False,
                error_message="Missing host, share, or username for SMB file upload.",
                auth_username=username_clean,
                auth_domain=domain_clean,
            )
        if not remote_name_clean:
            return SMBFileUploadResult(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode="missing",
                can_list_directory=False,
                error_message="Missing remote filename for SMB file upload.",
                auth_username=username_clean,
                auth_domain=domain_clean,
            )

        credential = str(password or "").strip()
        is_hash = _looks_like_ntlm_hash(credential)
        auth_mode = "kerberos" if use_kerberos else ("hash" if is_hash else "password")
        marked_host = mark_sensitive(host_clean, "host")
        marked_share = mark_sensitive(share_clean, "text")
        marked_directory = mark_sensitive(directory_clean or "\\", "path")
        marked_username = mark_sensitive(username_clean, "username")
        marked_domain = mark_sensitive(domain_clean or "<local>", "domain")
        print_info_debug(
            "[smb-path] starting file upload probe: "
            f"host={marked_host} share={marked_share} path={marked_directory} "
            f"user={marked_username} domain={marked_domain} "
            f"auth_mode={mark_sensitive(auth_mode, 'text')}"
        )

        # ASYNC_BOUNDARY: sync callers bridge to async here.
        result, exc = run_smb_operation(
            self._async_upload_file(
                host_clean=host_clean,
                share_clean=share_clean,
                directory_clean=directory_clean,
                username_clean=username_clean,
                domain_clean=domain_clean,
                credential=credential,
                auth_mode=auth_mode,
                is_hash=is_hash,
                use_kerberos=use_kerberos,
                kdc_host=kdc_host,
                spn_host=spn_host,
                timeout_seconds=timeout_seconds,
                remote_name_clean=remote_name_clean,
                file_contents=file_contents,
                delete_after=delete_after,
                marked_host=marked_host,
                marked_share=marked_share,
                marked_directory=marked_directory,
                marked_username=marked_username,
                marked_domain=marked_domain,
            )
        )

        if result.success:
            return result
        if exc is not None:
            telemetry.capture_exception(exc)
        print_warning_debug(
            "[smb-path] file upload failed: "
            f"host={marked_host} share={marked_share} path={marked_directory} "
            f"user={marked_username} domain={marked_domain} "
            f"auth_mode={mark_sensitive(result.auth_mode, 'text')} "
            f"status={mark_sensitive(result.status_code or '<unknown>', 'text')} "
            f"error={mark_sensitive(result.error_message or '', 'text')}"
        )
        if self._should_retry_with_ntlm(
            use_kerberos=use_kerberos,
            credential=credential,
            status_code=result.status_code,
            error_message=result.error_message,
        ):
            retry_auth_mode = "hash" if is_hash else "password"
            print_warning_debug(
                "[smb-path] retrying file upload with NTLM after Kerberos failure: "
                f"host={marked_host} share={marked_share} path={marked_directory} "
                f"user={marked_username} domain={marked_domain}"
            )
            retry_result, retry_exc = run_smb_operation(
                self._async_upload_file(
                    host_clean=host_clean,
                    share_clean=share_clean,
                    directory_clean=directory_clean,
                    username_clean=username_clean,
                    domain_clean=domain_clean,
                    credential=credential,
                    auth_mode=retry_auth_mode,
                    is_hash=is_hash,
                    use_kerberos=False,
                    kdc_host=None,
                    spn_host=spn_host,
                    timeout_seconds=timeout_seconds,
                    remote_name_clean=remote_name_clean,
                    file_contents=file_contents,
                    delete_after=delete_after,
                    marked_host=marked_host,
                    marked_share=marked_share,
                    marked_directory=marked_directory,
                    marked_username=marked_username,
                    marked_domain=marked_domain,
                )
            )
            if retry_result.success:
                return retry_result
            if retry_exc is not None:
                telemetry.capture_exception(retry_exc)
            print_warning_debug(
                "[smb-path] NTLM fallback upload failed: "
                f"host={marked_host} share={marked_share} path={marked_directory} "
                f"user={marked_username} domain={marked_domain} "
                f"auth_mode={mark_sensitive(retry_result.auth_mode, 'text')} "
                f"status={mark_sensitive(retry_result.status_code or '<unknown>', 'text')} "
                f"error={mark_sensitive(retry_result.error_message or '', 'text')}"
            )
            return retry_result
        return result

    def delete_file(
        self,
        *,
        target_host: str,
        share_name: str,
        file_path: str,
        username: str,
        password: str | None = None,
        auth_domain: str = "",
        use_kerberos: bool = False,
        kdc_host: str | None = None,
        spn_host: str | None = None,
        timeout_seconds: int = 30,
    ) -> SMBFileDeleteResult:
        """Delete one file from an SMB share/path."""
        share_clean = str(share_name or "").strip()
        host_clean = str(target_host or "").strip()
        username_clean = str(username or "").strip()
        domain_clean = str(auth_domain or "").strip()
        file_path_clean = str(file_path or "").strip().replace("/", "\\").strip("\\")
        if not host_clean or not share_clean or not username_clean or not file_path_clean:
            return SMBFileDeleteResult(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                file_path=file_path_clean,
                auth_mode="missing",
                error_message="Missing host, share, username, or file path for SMB file deletion.",
                auth_username=username_clean,
                auth_domain=domain_clean,
            )

        credential = str(password or "").strip()
        is_hash = _looks_like_ntlm_hash(credential)
        auth_mode = "kerberos" if use_kerberos else ("hash" if is_hash else "password")
        marked_host = mark_sensitive(host_clean, "host")
        marked_share = mark_sensitive(share_clean, "text")
        marked_file_path = mark_sensitive(file_path_clean, "path")
        marked_username = mark_sensitive(username_clean, "username")
        marked_domain = mark_sensitive(domain_clean or "<local>", "domain")
        print_info_debug(
            "[smb-path] starting file delete: "
            f"host={marked_host} share={marked_share} file={marked_file_path} "
            f"user={marked_username} domain={marked_domain} "
            f"auth_mode={mark_sensitive(auth_mode, 'text')}"
        )

        # ASYNC_BOUNDARY: sync callers bridge to async here.
        result, exc = run_smb_operation(
            self._async_delete_file(
                host_clean=host_clean,
                share_clean=share_clean,
                file_path_clean=file_path_clean,
                username_clean=username_clean,
                domain_clean=domain_clean,
                credential=credential,
                auth_mode=auth_mode,
                is_hash=is_hash,
                use_kerberos=use_kerberos,
                kdc_host=kdc_host,
                spn_host=spn_host,
                timeout_seconds=timeout_seconds,
                marked_host=marked_host,
                marked_share=marked_share,
                marked_file_path=marked_file_path,
                marked_username=marked_username,
                marked_domain=marked_domain,
            )
        )

        if result.success:
            return result
        if exc is not None:
            telemetry.capture_exception(exc)
        print_warning_debug(
            "[smb-path] file delete failed: "
            f"host={marked_host} share={marked_share} file={marked_file_path} "
            f"user={marked_username} domain={marked_domain} "
            f"auth_mode={mark_sensitive(result.auth_mode, 'text')} "
            f"status={mark_sensitive(result.status_code or '<unknown>', 'text')} "
            f"error={mark_sensitive(result.error_message or '', 'text')}"
        )
        if self._should_retry_with_ntlm(
            use_kerberos=use_kerberos,
            credential=credential,
            status_code=result.status_code,
            error_message=result.error_message,
        ):
            retry_auth_mode = "hash" if is_hash else "password"
            print_warning_debug(
                "[smb-path] retrying file delete with NTLM after Kerberos failure: "
                f"host={marked_host} share={marked_share} file={marked_file_path} "
                f"user={marked_username} domain={marked_domain}"
            )
            retry_result, retry_exc = run_smb_operation(
                self._async_delete_file(
                    host_clean=host_clean,
                    share_clean=share_clean,
                    file_path_clean=file_path_clean,
                    username_clean=username_clean,
                    domain_clean=domain_clean,
                    credential=credential,
                    auth_mode=retry_auth_mode,
                    is_hash=is_hash,
                    use_kerberos=False,
                    kdc_host=None,
                    spn_host=spn_host,
                    timeout_seconds=timeout_seconds,
                    marked_host=marked_host,
                    marked_share=marked_share,
                    marked_file_path=marked_file_path,
                    marked_username=marked_username,
                    marked_domain=marked_domain,
                )
            )
            if retry_result.success:
                return retry_result
            if retry_exc is not None:
                telemetry.capture_exception(retry_exc)
            print_warning_debug(
                "[smb-path] NTLM fallback delete failed: "
                f"host={marked_host} share={marked_share} file={marked_file_path} "
                f"user={marked_username} domain={marked_domain} "
                f"auth_mode={mark_sensitive(retry_result.auth_mode, 'text')} "
                f"status={mark_sensitive(retry_result.status_code or '<unknown>', 'text')} "
                f"error={mark_sensitive(retry_result.error_message or '', 'text')}"
            )
            return retry_result
        return result

    def probe_file_upload(
        self,
        *,
        target_host: str,
        share_name: str,
        directory_path: str = "",
        username: str,
        password: str | None = None,
        auth_domain: str = "",
        file_contents: bytes,
        filename_prefix: str = "adscan-write-probe-",
        filename_suffix: str = ".tmp",
        delete_after: bool = True,
        use_kerberos: bool = False,
        kdc_host: str | None = None,
        spn_host: str | None = None,
        timeout_seconds: int = 30,
    ) -> SMBPathWriteProbeResult:
        """Upload one probe file to an SMB path and optionally delete it afterwards."""
        upload_result = self.upload_file(
            target_host=target_host,
            share_name=share_name,
            directory_path=directory_path,
            username=username,
            password=password,
            auth_domain=auth_domain,
            file_contents=file_contents,
            remote_filename=f"{filename_prefix}{uuid4().hex}{filename_suffix}",
            delete_after=delete_after,
            use_kerberos=use_kerberos,
            kdc_host=kdc_host,
            spn_host=spn_host,
            timeout_seconds=timeout_seconds,
        )
        return SMBPathWriteProbeResult(
            success=upload_result.success,
            share_name=upload_result.share_name,
            directory_path=upload_result.directory_path,
            target_host=upload_result.target_host,
            can_list_directory=upload_result.can_list_directory,
            auth_mode=upload_result.auth_mode,
            can_write=upload_result.success,
            probed_file_path=upload_result.uploaded_file_path,
            error_message=upload_result.error_message,
            status_code=upload_result.status_code,
            auth_username=upload_result.auth_username,
            auth_domain=upload_result.auth_domain,
        )
