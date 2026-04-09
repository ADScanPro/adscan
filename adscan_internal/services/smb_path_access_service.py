"""Generic SMB path access checks backed by Impacket.

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


def _looks_like_ntlm_hash(value: str | None) -> bool:
    """Return whether one credential value resembles an NTLM hash."""
    candidate = str(value or "").strip()
    if not candidate:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
        return True
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", candidate))


def _extract_status_code(exc: Exception) -> str | None:
    """Return an NTSTATUS-like code from an Impacket SMB exception when available."""
    getter = getattr(exc, "getErrorString", None)
    if callable(getter):
        try:
            message = getter()
            if isinstance(message, tuple):
                for item in message:
                    text = str(item or "").strip()
                    if text:
                        return text
            text = str(message or "").strip()
            if text:
                return text
        except Exception:  # noqa: BLE001
            return None
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
    """Normalize one SMB directory path for Impacket operations."""
    normalized = str(directory_path or "").strip().replace("/", "\\")
    normalized = normalized.strip("\\")
    return normalized


def _coerce_bytes(value: object) -> bytes:
    """Return raw bytes for NDR/security-descriptor payloads when possible."""
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
        return bytes(value or b"")
    except Exception:  # noqa: BLE001
        return b""


def _unwrap_ndr_data(value: object) -> object:
    """Return the underlying NDR payload when wrapped in a ``Data`` pointer."""
    current = value
    for _ in range(2):
        if isinstance(current, dict) and "Data" in current:
            current = current["Data"]
            continue
        try:
            current = current["Data"]  # type: ignore[index]
            continue
        except Exception:  # noqa: BLE001
            pass
        break
    return current


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
        from impacket.ldap import ldaptypes  # type: ignore
    except Exception:
        return False, ()

    try:
        descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=descriptor_bytes)
    except Exception:
        return False, ()

    dacl = descriptor["Dacl"]
    if dacl == b"":
        return True, ("NULL_DACL",)

    denied_mask = 0
    granted_mask = 0
    matched_sids: list[str] = []
    for ace in getattr(dacl, "aces", []):
        ace_body = ace["Ace"]
        ace_sid_raw = ""
        try:
            ace_sid_raw = ace_body["Sid"].formatCanonical()
        except Exception:  # noqa: BLE001
            continue
        ace_sid = normalize_sid(ace_sid_raw or "")
        if not ace_sid or ace_sid not in candidate_sids:
            continue
        matched_sids.append(ace_sid)
        try:
            ace_mask = int(ace_body["Mask"]["Mask"])
        except Exception:  # noqa: BLE001
            continue
        try:
            type_name = str(ace["TypeName"] or "").upper()
        except Exception:  # noqa: BLE001
            type_name = ""
        if "DENIED" in type_name:
            denied_mask |= ace_mask
            granted_mask &= ~ace_mask
            continue
        if "ALLOWED" in type_name:
            granted_mask |= ace_mask & ~denied_mask

    return _mask_includes_write(granted_mask), tuple(dict.fromkeys(matched_sids))


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
    """Perform generic SMB share/path write probes with Impacket."""

    def _build_connection(
        self,
        *,
        target_host: str,
        timeout_seconds: int,
    ) -> object:
        """Return one authenticated-capable SMB connection object."""
        from impacket.smbconnection import SMBConnection  # type: ignore

        return SMBConnection(
            remoteName=target_host,
            remoteHost=target_host,
            sess_port=445,
            timeout=timeout_seconds,
        )

    def _authenticate_connection(
        self,
        *,
        connection: object,
        username: str,
        credential: str,
        auth_domain: str,
        auth_mode: str,
        kdc_host: str | None,
    ) -> None:
        """Authenticate one SMB connection according to the selected auth mode."""
        if auth_mode == "kerberos":
            lmhash = ""
            nthash = ""
            if _looks_like_ntlm_hash(credential):
                if ":" in credential:
                    lmhash, nthash = credential.split(":", 1)
                else:
                    nthash = credential
            connection.kerberosLogin(  # type: ignore[attr-defined]
                user=username,
                password="" if _looks_like_ntlm_hash(credential) else credential,
                domain=auth_domain,
                lmhash=lmhash,
                nthash=nthash,
                kdcHost=str(kdc_host or "").strip() or None,
                useCache=True,
            )
            return
        if auth_mode == "hash":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
            nthash = credential
            if ":" in credential:
                lmhash, nthash = credential.split(":", 1)
            connection.login(  # type: ignore[attr-defined]
                user=username,
                password="",
                domain=auth_domain,
                lmhash=lmhash,
                nthash=nthash,
            )
            return
        connection.login(  # type: ignore[attr-defined]
            user=username,
            password=credential,
            domain=auth_domain,
        )

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

    def _get_share_security_descriptor(
        self,
        *,
        connection: object,
        share_name: str,
    ) -> tuple[bytes, str]:
        """Return the share security descriptor and backing path for one SMB share."""
        from impacket.dcerpc.v5 import srvs, transport  # type: ignore

        rpc_transport = transport.SMBTransport(
            connection.getRemoteName(),  # type: ignore[attr-defined]
            connection.getRemoteHost(),  # type: ignore[attr-defined]
            filename=r"\srvsvc",
            smb_connection=connection,
        )
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        try:
            response = srvs.hNetrShareGetInfo(dce, share_name, 502)
        finally:
            try:
                dce.disconnect()
            except Exception:  # noqa: BLE001
                pass

        share_info = _unwrap_ndr_data(response["InfoStruct"]["ShareInfo502"])
        descriptor_bytes = _coerce_bytes(
            share_info["shi502_security_descriptor"] if isinstance(share_info, dict) else share_info["shi502_security_descriptor"]
        )
        backing_path = str(
            share_info["shi502_path"] if isinstance(share_info, dict) else share_info["shi502_path"]
        ).strip()
        return descriptor_bytes, backing_path

    def _get_path_security_descriptor(
        self,
        *,
        connection: object,
        share_name: str,
        directory_path: str,
    ) -> bytes:
        """Return one directory security descriptor from the target share/path."""
        from impacket import smb  # type: ignore
        from impacket.smb3structs import (  # type: ignore
            DACL_SECURITY_INFORMATION,
            FILE_DIRECTORY_FILE,
            FILE_OPEN,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE,
            FILE_SHARE_READ,
            FILE_SHARE_WRITE,
            GROUP_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION,
            READ_CONTROL,
            SMB2_0_INFO_SECURITY,
        )

        tree_id = connection.connectTree(share_name)  # type: ignore[attr-defined]
        security_information = (
            OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
        )
        last_error: Exception | None = None
        for candidate_path in _candidate_directory_open_paths(directory_path):
            file_id = None
            try:
                file_id = connection.openFile(  # type: ignore[attr-defined]
                    tree_id,
                    candidate_path,
                    desiredAccess=READ_CONTROL | FILE_READ_ATTRIBUTES,
                    shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    creationOption=FILE_DIRECTORY_FILE,
                    creationDisposition=FILE_OPEN,
                )
                smb_server = connection.getSMBServer()  # type: ignore[attr-defined]
                if connection.getDialect() == smb.SMB_DIALECT:  # type: ignore[attr-defined]
                    return _coerce_bytes(
                        smb_server.query_sec_info(
                            tree_id,
                            file_id,
                            additional_information=security_information,
                        )
                    )
                return _coerce_bytes(
                    smb_server.queryInfo(
                        tree_id,
                        file_id,
                        infoType=SMB2_0_INFO_SECURITY,
                        fileInfoClass=0,
                        additionalInformation=security_information,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
            finally:
                if file_id is not None:
                    try:
                        connection.closeFile(tree_id, file_id)  # type: ignore[attr-defined]
                    except Exception:  # noqa: BLE001
                        pass
        if last_error is not None:
            raise last_error
        return b""

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

        connection = None
        share_descriptor_readable = False
        path_descriptor_readable = False
        share_descriptor = b""
        path_descriptor = b""
        share_backing_path = ""
        try:
            from impacket.smbconnection import SessionError  # type: ignore
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return SMBPathSecuritySnapshot(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode="unavailable",
                share_descriptor_readable=False,
                path_descriptor_readable=False,
                error_message=f"Impacket SMB support is unavailable: {exc}",
                auth_username=username_clean,
                auth_domain=domain_clean,
            )

        try:
            connection = self._build_connection(
                target_host=host_clean,
                timeout_seconds=timeout_seconds,
            )
            self._authenticate_connection(
                connection=connection,
                username=username_clean,
                credential=credential,
                auth_domain=domain_clean,
                auth_mode=auth_mode,
                kdc_host=kdc_host,
            )
            try:
                share_descriptor, share_backing_path = self._get_share_security_descriptor(
                    connection=connection,
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
                path_descriptor = self._get_path_security_descriptor(
                    connection=connection,
                    share_name=share_clean,
                    directory_path=directory_clean,
                )
                path_descriptor_readable = bool(path_descriptor)
                if path_descriptor_readable:
                    print_info_verbose(
                        "[smb-path] path security descriptor collected: "
                        f"host={marked_host} share={marked_share} path={marked_directory}"
                    )
            except SessionError as exc:
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
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
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
        finally:
            if connection is not None:
                try:
                    connection.logoff()  # type: ignore[attr-defined]
                except Exception:  # noqa: BLE001
                    pass

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

        try:
            from impacket.smbconnection import SMBConnection, SessionError  # type: ignore
            from impacket.smb3structs import (  # type: ignore
                FILE_CREATE,
                FILE_DELETE_ON_CLOSE,
                FILE_NON_DIRECTORY_FILE,
                FILE_SHARE_DELETE,
                FILE_SHARE_READ,
                FILE_SHARE_WRITE,
                GENERIC_WRITE,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return SMBPathWriteProbeResult(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode="unavailable",
                can_list_directory=False,
                can_write=False,
                error_message=f"Impacket SMB support is unavailable: {exc}",
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

        connection = None
        can_list_directory = False
        probe_path = ""
        try:
            connection = SMBConnection(
                remoteName=host_clean,
                remoteHost=host_clean,
                sess_port=445,
                timeout=timeout_seconds,
            )
            if use_kerberos:
                lmhash = ""
                nthash = ""
                if is_hash:
                    if ":" in credential:
                        lmhash, nthash = credential.split(":", 1)
                    else:
                        nthash = credential
                connection.kerberosLogin(
                    user=username_clean,
                    password="" if is_hash else credential,
                    domain=domain_clean,
                    lmhash=lmhash,
                    nthash=nthash,
                    kdcHost=str(kdc_host or "").strip() or None,
                    useCache=True,
                )
            elif is_hash:
                lmhash = "aad3b435b51404eeaad3b435b51404ee"
                nthash = credential
                if ":" in credential:
                    lmhash, nthash = credential.split(":", 1)
                connection.login(
                    user=username_clean,
                    password="",
                    domain=domain_clean,
                    lmhash=lmhash,
                    nthash=nthash,
                )
            else:
                connection.login(
                    user=username_clean,
                    password=credential,
                    domain=domain_clean,
                )

            list_pattern = f"{directory_clean}\\*" if directory_clean else "*"
            try:
                connection.listPath(share_clean, list_pattern)
                can_list_directory = True
                print_info_verbose(
                    "[smb-path] directory listing succeeded: "
                    f"host={marked_host} share={marked_share} path={marked_directory}"
                )
            except SessionError:
                can_list_directory = False
                print_warning_debug(
                    "[smb-path] directory listing was denied but write probe will continue: "
                    f"host={marked_host} share={marked_share} path={marked_directory}"
                )

            probe_name = f".adscan-write-probe-{uuid4().hex}.tmp"
            probe_path = f"{directory_clean}\\{probe_name}" if directory_clean else probe_name
            tree_id = connection.connectTree(share_clean)
            file_id = connection.createFile(
                tree_id,
                probe_path,
                desiredAccess=GENERIC_WRITE,
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                creationOption=FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
                creationDisposition=FILE_CREATE,
            )
            connection.closeFile(tree_id, file_id)
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
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
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
        finally:
            if connection is not None:
                try:
                    connection.logoff()
                except Exception:  # noqa: BLE001
                    pass

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

        try:
            from impacket.smbconnection import SessionError  # type: ignore
            from impacket.smb3structs import (  # type: ignore
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE,
                FILE_SHARE_DELETE,
                FILE_SHARE_READ,
                FILE_SHARE_WRITE,
                GENERIC_WRITE,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return SMBFileUploadResult(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                directory_path=directory_clean,
                auth_mode="unavailable",
                can_list_directory=False,
                error_message=f"Impacket SMB support is unavailable: {exc}",
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

        def _attempt_upload(attempt_auth_mode: str, attempt_use_kerberos: bool) -> tuple[SMBFileUploadResult, Exception | None]:
            connection = None
            can_list_directory = False
            uploaded_path = ""
            deleted_after_successfully = False
            try:
                connection = self._build_connection(
                    target_host=host_clean,
                    timeout_seconds=timeout_seconds,
                )
                self._authenticate_connection(
                    connection=connection,
                    username=username_clean,
                    credential=credential,
                    auth_domain=domain_clean,
                    auth_mode=attempt_auth_mode,
                    kdc_host=kdc_host if attempt_use_kerberos else None,
                )
                list_pattern = f"{directory_clean}\\*" if directory_clean else "*"
                try:
                    connection.listPath(share_clean, list_pattern)  # type: ignore[attr-defined]
                    can_list_directory = True
                    print_info_verbose(
                        "[smb-path] directory listing succeeded before upload probe: "
                        f"host={marked_host} share={marked_share} path={marked_directory}"
                    )
                except SessionError:
                    print_warning_debug(
                        "[smb-path] directory listing was denied before file upload; "
                        f"upload will continue: host={marked_host} share={marked_share} "
                        f"path={marked_directory}"
                    )
                uploaded_path = (
                    f"{directory_clean}\\{remote_name_clean}" if directory_clean else remote_name_clean
                )
                tree_id = connection.connectTree(share_clean)  # type: ignore[attr-defined]
                file_id = connection.createFile(  # type: ignore[attr-defined]
                    tree_id,
                    uploaded_path,
                    desiredAccess=GENERIC_WRITE,
                    shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    creationOption=FILE_NON_DIRECTORY_FILE,
                    creationDisposition=FILE_CREATE,
                )
                try:
                    connection.writeFile(tree_id, file_id, file_contents)  # type: ignore[attr-defined]
                finally:
                    connection.closeFile(tree_id, file_id)  # type: ignore[attr-defined]
                if delete_after:
                    try:
                        connection.deleteFile(share_clean, uploaded_path)  # type: ignore[attr-defined]
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
                    f"auth_mode={mark_sensitive(attempt_auth_mode, 'text')}"
                )
                return (
                    SMBFileUploadResult(
                        success=True,
                        target_host=host_clean,
                        share_name=share_clean,
                        directory_path=directory_clean,
                        can_list_directory=can_list_directory,
                        auth_mode=attempt_auth_mode,
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
                        auth_mode=attempt_auth_mode,
                        uploaded_file_path=uploaded_path,
                        error_message=str(exc),
                        status_code=_extract_status_code(exc),
                        auth_username=username_clean,
                        auth_domain=domain_clean,
                    ),
                    exc,
                )
            finally:
                if connection is not None:
                    try:
                        connection.logoff()
                    except Exception:  # noqa: BLE001
                        pass

        result, exc = _attempt_upload(auth_mode, use_kerberos)
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
            retry_result, retry_exc = _attempt_upload(retry_auth_mode, False)
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

        try:
            from impacket.smbconnection import SMBConnection  # type: ignore  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return SMBFileDeleteResult(
                success=False,
                target_host=host_clean,
                share_name=share_clean,
                file_path=file_path_clean,
                auth_mode="unavailable",
                error_message=f"Impacket SMB support is unavailable: {exc}",
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

        def _attempt_delete(attempt_auth_mode: str, attempt_use_kerberos: bool) -> tuple[SMBFileDeleteResult, Exception | None]:
            connection = None
            try:
                connection = self._build_connection(
                    target_host=host_clean,
                    timeout_seconds=timeout_seconds,
                )
                self._authenticate_connection(
                    connection=connection,
                    username=username_clean,
                    credential=credential,
                    auth_domain=domain_clean,
                    auth_mode=attempt_auth_mode,
                    kdc_host=kdc_host if attempt_use_kerberos else None,
                )
                connection.deleteFile(share_clean, file_path_clean)  # type: ignore[attr-defined]
                print_success_debug(
                    "[smb-path] file delete succeeded: "
                    f"host={marked_host} share={marked_share} file={marked_file_path} "
                    f"auth_mode={mark_sensitive(attempt_auth_mode, 'text')}"
                )
                return (
                    SMBFileDeleteResult(
                        success=True,
                        target_host=host_clean,
                        share_name=share_clean,
                        file_path=file_path_clean,
                        auth_mode=attempt_auth_mode,
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
                        auth_mode=attempt_auth_mode,
                        error_message=str(exc),
                        status_code=_extract_status_code(exc),
                        auth_username=username_clean,
                        auth_domain=domain_clean,
                    ),
                    exc,
                )
            finally:
                if connection is not None:
                    try:
                        connection.logoff()
                    except Exception:  # noqa: BLE001
                        pass

        result, exc = _attempt_delete(auth_mode, use_kerberos)
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
            retry_result, retry_exc = _attempt_delete(retry_auth_mode, False)
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
