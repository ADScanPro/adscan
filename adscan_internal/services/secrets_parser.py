"""In-process pypykatz adapter for LSASS and offline registry parsing.

Replaces subprocess invocations of the pypykatz CLI with direct library calls.
All sync pypykatz calls are wrapped in asyncio.to_thread so callers that already
run in an async context can await them without blocking the event loop.

Callers that are still synchronous should use asyncio.run() at the boundary
(marked # ASYNC_BOUNDARY) or call the _sync_* variants defined here.
"""

from __future__ import annotations

import asyncio
import io
from dataclasses import dataclass, field

from adscan_core.rich_output import print_info_debug, print_info_verbose
from adscan_internal import telemetry
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class SecretsParserError(Exception):
    """Raised when pypykatz parsing fails; wraps the original exception."""


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------


@dataclass
class LocalUserCredential:
    """Credential parsed from an offline SAM hive."""

    username: str
    rid: int
    lm_hash: str  # "aad3b435..." or empty string
    nt_hash: str  # 32 hex chars or empty string


@dataclass
class LSASecrets:
    """Secrets parsed from an offline SECURITY hive."""

    machine_account_nt_hash: str | None  # $MACHINE.ACC NT hash (hex)
    machine_account_password_raw: bytes | None  # raw bytes for $MACHINE.ACC
    machine_account_kerberos_password: bytes | None = None  # raw Kerberos pw bytes for AES key derivation
    dpapi_machine_key: bytes | None = None  # DPAPI_SYSTEM machine key
    dpapi_user_key: bytes | None = None  # DPAPI_SYSTEM user key
    cached_domain_logons: list[str] = field(default_factory=list)  # DCC2 hashes in hashcat 2100 format
    service_secrets: dict[str, str] = field(default_factory=dict)  # key_name -> decoded secret string
    security_questions: dict[str, list[dict]] = field(default_factory=dict)  # SID -> [{question, answer}]
    raw_secrets: list[dict] = field(default_factory=list)  # full to_dict() output from LSASecret objects


@dataclass
class MsvCredential:
    """MSV credential parsed from an LSASS dump."""

    username: str
    domain: str
    nt_hash: str  # hex or empty
    lm_hash: str  # hex or empty
    sha1: str  # hex or empty


@dataclass
class LSASSCredentials:
    """Structured result from parsing a full LSASS minidump."""

    msv: list[MsvCredential] = field(default_factory=list)
    # kerberos_hashes: present in logon_sessions but not extracted here —
    # callers currently only need MSV NT hashes. Extend if needed.


# ---------------------------------------------------------------------------
# LSASS minidump
# ---------------------------------------------------------------------------


def _sync_parse_lsass_dump(dump_bytes: bytes) -> LSASSCredentials:
    """Synchronously parse LSASS minidump bytes using pypykatz library.

    Uses parse_minidump_buffer (io.BytesIO) to avoid writing to disk.
    """
    try:
        from pypykatz.pypykatz import pypykatz as Pypykatz  # type: ignore[import-untyped]
    except ImportError as exc:
        raise SecretsParserError(
            "pypykatz is not installed. Run 'adscan install' to install dependencies."
        ) from exc

    try:
        buff = io.BytesIO(dump_bytes)
        mimi = Pypykatz.parse_minidump_buffer(buff)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        raise SecretsParserError(f"pypykatz minidump parse error: {exc}") from exc

    msv_creds: list[MsvCredential] = []
    seen: set[tuple[str, str]] = set()

    for luid, session in mimi.logon_sessions.items():
        _ = luid
        username: str = str(session.username or "").strip()
        domain: str = str(session.domainname or "").strip()
        if not username or username.startswith(("UMFD-", "DWM-")):
            continue
        for msv in session.msv_creds:
            try:
                nt_hash = msv.NThash.hex() if msv.NThash else ""
                lm_hash = msv.LMHash.hex() if getattr(msv, "LMHash", None) else ""
                sha1 = msv.SHAHash.hex() if getattr(msv, "SHAHash", None) else ""
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(f"[secrets_parser] failed to hex-encode hash for {username}: {exc}")
                continue
            dedup_key = (username.lower(), nt_hash)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            msv_creds.append(
                MsvCredential(
                    username=username,
                    domain=domain,
                    nt_hash=nt_hash,
                    lm_hash=lm_hash,
                    sha1=sha1,
                )
            )

    print_info_debug(
        f"[secrets_parser] parse_lsass_dump extracted {len(msv_creds)} MSV credential(s)"
    )
    return LSASSCredentials(msv=msv_creds)


async def parse_lsass_dump(dump_bytes: bytes) -> LSASSCredentials:
    """Parse LSASS minidump bytes using pypykatz library.

    Wraps the synchronous parser in asyncio.to_thread so async callers do not
    block the event loop.
    """
    return await asyncio.to_thread(_sync_parse_lsass_dump, dump_bytes)


# ---------------------------------------------------------------------------
# Offline SAM hive
# ---------------------------------------------------------------------------


def _sync_parse_sam_hive(sam_bytes: bytes, system_bytes: bytes) -> list[LocalUserCredential]:
    """Synchronously parse an offline SAM hive using pypykatz library.

    Uses OffineRegistry.from_bytes() — accepts bytes directly, no tempfile needed.
    """
    try:
        from pypykatz.registry.offline_parser import OffineRegistry  # type: ignore[import-untyped]
    except ImportError as exc:
        raise SecretsParserError(
            "pypykatz is not installed. Run 'adscan install' to install dependencies."
        ) from exc

    try:
        registry = OffineRegistry.from_bytes(
            system_data=system_bytes,
            sam_data=sam_bytes,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        raise SecretsParserError(f"pypykatz SAM parse error: {exc}") from exc

    results: list[LocalUserCredential] = []
    if registry.sam is None:
        print_info_verbose("[secrets_parser] SAM section is empty after parsing")
        return results

    for secret in registry.sam.secrets:
        try:
            username: str = str(secret.username or "").strip()
            rid: int = int(secret.rid or 0)
            nt_hash: str = secret.nt_hash.hex() if secret.nt_hash else ""
            lm_hash: str = secret.lm_hash.hex() if secret.lm_hash else ""
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[secrets_parser] skipping SAM secret due to parse error: {exc}")
            continue
        results.append(
            LocalUserCredential(
                username=username,
                rid=rid,
                lm_hash=lm_hash,
                nt_hash=nt_hash,
            )
        )

    print_info_debug(
        f"[secrets_parser] parse_sam_hive extracted {len(results)} local user(s)"
    )
    return results


async def parse_sam_hive(sam_bytes: bytes, system_bytes: bytes) -> list[LocalUserCredential]:
    """Parse an offline SAM hive for local user NT hashes.

    Wraps the sync parser in asyncio.to_thread.
    """
    return await asyncio.to_thread(_sync_parse_sam_hive, sam_bytes, system_bytes)


# ---------------------------------------------------------------------------
# Offline SECURITY hive (LSA secrets)
# ---------------------------------------------------------------------------


def _sync_parse_lsa_secrets(
    security_bytes: bytes,
    system_bytes: bytes,
    *,
    winlogon_default_user: str | None = None,
) -> LSASecrets:
    """Synchronously parse SECURITY hive for LSA secrets using pypykatz library."""
    try:
        from pypykatz.registry.offline_parser import OffineRegistry  # type: ignore[import-untyped]
        from pypykatz.registry.security.common import (  # type: ignore[import-untyped]
            LSASecret,
            LSASecretASPNET,
            LSASecretDPAPI,
            LSASecretDefaultPassword,
            LSASecretMachineAccount,
            LSASecretService,
        )
    except ImportError as exc:
        raise SecretsParserError(
            "pypykatz is not installed. Run 'adscan install' to install dependencies."
        ) from exc

    try:
        registry = OffineRegistry.from_bytes(
            system_data=system_bytes,
            security_data=security_bytes,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        raise SecretsParserError(f"pypykatz SECURITY parse error: {exc}") from exc

    machine_nt_hash: str | None = None
    machine_raw: bytes | None = None
    machine_kerberos_pw: bytes | None = None
    dpapi_machine: bytes | None = None
    dpapi_user: bytes | None = None
    dcc_hashes: list[str] = []
    service_secrets: dict[str, str] = {}
    security_questions: dict[str, list[dict]] = {}
    raw_secrets: list[dict] = []

    if registry.security is None:
        print_info_verbose("[secrets_parser] SECURITY section is empty after parsing")
        return LSASecrets(
            machine_account_nt_hash=None,
            machine_account_password_raw=None,
        )

    for secret in registry.security.cached_secrets:
        try:
            raw_secrets.append(secret.to_dict())
            if isinstance(secret, LSASecretMachineAccount):
                candidate_hash = secret.secret.hex() if secret.secret else None
                candidate_raw = secret.raw_secret
                candidate_kpw = getattr(secret, "kerberos_password", None)
                is_history = bool(getattr(secret, "history", False))
                print_info_debug(
                    f"[secrets_parser] $MACHINE.ACC raw_secret: "
                    f"len={len(candidate_raw) if candidate_raw else 0} "
                    f"first16={candidate_raw[:16].hex() if candidate_raw else ''} "
                    f"nt_hash={candidate_hash} "
                    f"kerberos_pw={'yes' if candidate_kpw else 'no'} "
                    f"history={is_history}"
                )
                # Prefer the current password (history=False) over the old one.
                # pypykatz stores both current and history entries; the history
                # entry is the previous password — unusable for authentication.
                if not is_history:
                    machine_nt_hash = candidate_hash
                    machine_raw = candidate_raw
                    machine_kerberos_pw = candidate_kpw or machine_kerberos_pw
                elif machine_nt_hash is None:
                    machine_nt_hash = candidate_hash
                    machine_raw = candidate_raw
                    machine_kerberos_pw = candidate_kpw
            elif isinstance(secret, LSASecretDPAPI):
                # Same history-first rule: prefer current (history=False) DPAPI keys.
                is_history = bool(getattr(secret, "history", False))
                if not is_history:
                    dpapi_machine = secret.machine_key
                    dpapi_user = secret.user_key
                elif dpapi_machine is None:
                    dpapi_machine = secret.machine_key
                    dpapi_user = secret.user_key
            elif isinstance(secret, LSASecretService):
                # Service account passwords: skip history entries to avoid
                # overwriting the current password with the old one when the
                # key_name is identical for both CurrVal and OldVal iterations.
                is_history = bool(getattr(secret, "history", False))
                svc_key = str(secret.key_name or "")
                if not is_history or svc_key not in service_secrets:
                    svc_secret = secret.secret or ""
                    service_secrets[svc_key] = str(svc_secret)
            elif isinstance(secret, LSASecretDefaultPassword):
                # AutoLogon / DefaultPassword LSA secret.
                # Use the actual owner username when available (read from
                # HKLM\SOFTWARE\...\Winlogon\DefaultUserName — same lookup
                # impacket performs via getDefaultLoginAccount()).  Falls back
                # to the raw key name when the Winlogon query was not possible.
                is_history = bool(getattr(secret, "history", False))
                if is_history and winlogon_default_user:
                    # History entry — suppress when we already know the real owner.
                    # The old password belongs to the same user but is expired/stale.
                    # Without suppression it would land in service_secrets under the
                    # raw key "DEFAULTPASSWORD" and be persisted as a wrong-username
                    # credential after the attributed current entry.
                    pass
                else:
                    svc_key = (
                        winlogon_default_user
                        if (winlogon_default_user and not is_history)
                        else str(secret.key_name or "DefaultPassword")
                    )
                    if not is_history or svc_key not in service_secrets:
                        service_secrets[svc_key] = str(secret.secret or "")
            elif isinstance(secret, LSASecretASPNET):
                # IIS / ASP.NET Worker Process password for the ASPNET service
                # account — plaintext credential for the account that runs IIS
                # app pools under older Windows configurations.
                is_history = bool(getattr(secret, "history", False))
                svc_key = str(secret.key_name or "ASPNET_WP_PASSWORD")
                if not is_history or svc_key not in service_secrets:
                    svc_secret = getattr(secret, "secret", None) or ""
                    service_secrets[svc_key] = str(svc_secret)
            elif isinstance(secret, LSASecret):
                # Base LSASecret for unrecognized keys (NL$KM, L$_SQSA_*, etc.)
                key_name = str(secret.key_name or "")
                raw = secret.raw_secret
                is_history = bool(getattr(secret, "history", False))
                if key_name.upper().startswith("L$_SQSA_") and raw and not is_history:
                    # Windows Hello / Security Questions: UTF-16LE JSON blob.
                    # Key name format: L$_SQSA_{SID}.
                    # impacket reference: secretsdump.py ~L2261.
                    sid = key_name[len("L$_SQSA_"):]
                    try:
                        import json as _json
                        decoded = raw.decode("utf-16le").replace("\xa0", " ")
                        parsed = _json.loads(decoded)
                        if isinstance(parsed, dict) and "questions" in parsed:
                            security_questions[sid] = [
                                {"question": q.get("question", ""), "answer": q.get("answer", "")}
                                for q in parsed.get("questions", [])
                            ]
                    except Exception as sqsa_exc:  # noqa: BLE001
                        telemetry.capture_exception(sqsa_exc)
                        print_exception(exception=sqsa_exc)
                        print_info_debug(
                            f"[secrets_parser] L$_SQSA parse failed for {sid}: {sqsa_exc}"
                        )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[secrets_parser] error processing LSA secret: {exc}")

    for dcc in registry.security.dcc_hashes:
        try:
            dcc_hashes.append(str(dcc))
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[secrets_parser] error processing DCC hash: {exc}")

    print_info_debug(
        f"[secrets_parser] parse_lsa_secrets: machine_acc={'yes' if machine_nt_hash else 'no'}, "
        f"dpapi={'yes' if dpapi_machine else 'no'}, "
        f"dcc={len(dcc_hashes)}, svc={len(service_secrets)}"
    )
    return LSASecrets(
        machine_account_nt_hash=machine_nt_hash,
        machine_account_password_raw=machine_raw,
        machine_account_kerberos_password=machine_kerberos_pw,
        dpapi_machine_key=dpapi_machine,
        dpapi_user_key=dpapi_user,
        cached_domain_logons=dcc_hashes,
        service_secrets=service_secrets,
        security_questions=security_questions,
        raw_secrets=raw_secrets,
    )


async def parse_lsa_secrets(
    security_bytes: bytes,
    system_bytes: bytes,
    *,
    winlogon_default_user: str | None = None,
) -> LSASecrets:
    """Parse offline SECURITY hive for LSA secrets.

    Wraps the sync parser in asyncio.to_thread.

    Args:
        winlogon_default_user: Optional value of
            ``HKLM\\SOFTWARE\\...\\Winlogon\\DefaultUserName`` read from the
            target during the SMB session.  When provided, the
            ``DEFAULTPASSWORD`` LSA secret is attributed to this user instead
            of the raw ``"DEFAULTPASSWORD"`` key name.
    """
    return await asyncio.to_thread(
        _sync_parse_lsa_secrets, security_bytes, system_bytes,
        winlogon_default_user=winlogon_default_user,
    )


# ---------------------------------------------------------------------------
# NTDS — DECISION PENDING
# ---------------------------------------------------------------------------

# DECISION PENDING: pypykatz API mismatch — expected pypykatz/ntds/ module with
# get_impacket_hashes() or equivalent, found no ntds sub-package in
# vendor/pypykatz/pypykatz/. The pypykatz 0.6.13 version shipped under
# vendor/ does not include NTDS parsing capability. ADscan's current
# code does not call pypykatz for NTDS either (uses impacket secretsdump.py
# subprocess for that path — see dumps.py:run_secretsdump_registries). No
# replacement is implemented here; the subprocess path is preserved as-is.
#
# If a future pypykatz version adds NTDS support, implement:
#   async def parse_ntds(ntds_path: Path, system_bytes: bytes) -> AsyncIterator[DomainCredential]:
# using asyncio.to_thread + asyncio.Queue shim per the migration spec.


# ---------------------------------------------------------------------------
# Synchronous convenience wrappers (for sync call boundaries)
# ---------------------------------------------------------------------------


def sync_parse_lsass_dump(dump_bytes: bytes) -> LSASSCredentials:
    """Synchronous entry point for callers that cannot await.

    Delegates to _sync_parse_lsass_dump directly without creating a new event
    loop, which avoids nested-loop issues when called from within an existing
    sync context.
    """
    return _sync_parse_lsass_dump(dump_bytes)


def sync_parse_sam_hive(sam_bytes: bytes, system_bytes: bytes) -> list[LocalUserCredential]:
    """Synchronous entry point for parse_sam_hive."""
    return _sync_parse_sam_hive(sam_bytes, system_bytes)


def sync_parse_lsa_secrets(
    security_bytes: bytes,
    system_bytes: bytes,
    *,
    winlogon_default_user: str | None = None,
) -> LSASecrets:
    """Synchronous entry point for parse_lsa_secrets."""
    return _sync_parse_lsa_secrets(
        security_bytes, system_bytes,
        winlogon_default_user=winlogon_default_user,
    )
