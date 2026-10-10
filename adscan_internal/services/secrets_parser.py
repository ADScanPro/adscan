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
    # key_name -> raw undecoded bytes. Not every ``_SC_*`` secret is a string:
    # ``_SC_GMSA_{GUID}_<hash>`` is an MSDS_MANAGEDPASSWORD_BLOB and only the raw
    # bytes can be parsed into credentials, so they must survive the decode step.
    service_secrets_raw: dict[str, bytes] = field(default_factory=dict)
    # key_name -> service logon account, when the offline SYSTEM hive could be
    # walked. Usually empty: the ``Services`` subkey list on a real server uses
    # an index-leaf record the offline hive reader does not traverse, which is
    # why the live remote-registry lookup is the primary source.
    service_secret_owners: dict[str, str] = field(default_factory=dict)
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


def map_sam_secrets(sam_obj) -> list[LocalUserCredential]:
    """Map a pypykatz SAM object's secrets into ADscan's ``LocalUserCredential`` model.

    ``sam_obj`` is a ``pypykatz.registry.sam.common``-shaped object exposing
    ``.secrets`` (each a username/rid/nt_hash/lm_hash record). It is produced
    identically by two backends — ``OffineRegistry.from_bytes(...).sam`` (the
    byte-based SaveKey path, via :func:`_sync_parse_sam_hive`) and
    ``pypykatz.registry.remote_parser.RemoteRegistry(...).sam`` (the inline
    SeBackupPrivilege read, via the ``read_registry_secrets`` SSOT in
    ``native_dump_service.py``) — so both MUST route through this one mapper
    to keep the client-facing model byte-identical regardless of extraction
    method. See docs/superpowers/specs/2026-10-06-registry-secrets-inline-read-ssot-design.md.
    """
    results: list[LocalUserCredential] = []
    if sam_obj is None:
        print_info_verbose("[secrets_parser] SAM section is empty after parsing")
        return results

    for secret in sam_obj.secrets:
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
        f"[secrets_parser] map_sam_secrets extracted {len(results)} local user(s)"
    )
    return results


def _sync_parse_sam_hive(sam_bytes: bytes, system_bytes: bytes) -> list[LocalUserCredential]:
    """Synchronously parse an offline SAM hive using pypykatz library.

    Uses OffineRegistry.from_bytes() — accepts bytes directly, no tempfile needed.
    Thin wrapper: parses bytes into a pypykatz SAM object, then delegates the
    object-to-model mapping to :func:`map_sam_secrets` (the shared SSOT also
    used by the inline backend).
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

    return map_sam_secrets(registry.sam)


async def parse_sam_hive(sam_bytes: bytes, system_bytes: bytes) -> list[LocalUserCredential]:
    """Parse an offline SAM hive for local user NT hashes.

    Wraps the sync parser in asyncio.to_thread.
    """
    return await asyncio.to_thread(_sync_parse_sam_hive, sam_bytes, system_bytes)


# ---------------------------------------------------------------------------
# Offline SECURITY hive (LSA secrets)
# ---------------------------------------------------------------------------


def map_security_secrets(
    security_obj,
    *,
    winlogon_default_user: str | None = None,
) -> LSASecrets:
    """Map a pypykatz SECURITY object's cached secrets into ADscan's ``LSASecrets`` model.

    ``security_obj`` exposes ``.cached_secrets`` and ``.dcc_hashes``, and is
    produced by two backends — ``OffineRegistry.from_bytes(...).security``
    (the byte-based SaveKey path, via :func:`_sync_parse_lsa_secrets`) and
    ``pypykatz.registry.remote_parser.RemoteRegistry(...).security`` (the
    inline SeBackupPrivilege read, via the ``read_registry_secrets`` SSOT in
    ``native_dump_service.py``) — so both MUST route through this one mapper
    to keep the client-facing model byte-identical regardless of extraction
    method. See docs/superpowers/specs/2026-10-06-registry-secrets-inline-read-ssot-design.md.

    **pypykatz landmine — the two backends do NOT yield the same classes.**
    ``cached_secrets`` entries from the offline/bytes backend are instances of
    ``pypykatz.registry.security.common.LSASecret*`` (the sync hierarchy);
    entries from the inline/live ``RemoteRegistry`` backend are instances of
    ``pypykatz.registry.security.acommon.LSASecret*`` (a SEPARATE async
    hierarchy pypykatz's own ``asecurity.py`` imports from — same names, same
    constructor shapes, but ``is not`` the same class objects as the sync
    ones). An ``isinstance`` check against only ONE hierarchy silently matches
    NOTHING for the other backend's secrets — no exception, `cached_secrets`
    has entries, `map_security_secrets` returns an EMPTY model. This is a real
    regression that shipped and was caught live against GOAD winterfell
    (inline returned 0 secrets where the byte path found 7) before being
    fixed here by checking BOTH hierarchies on every ``isinstance``. Do not
    "simplify" this back down to one import.

    ``winlogon_default_user`` is the DefaultUserName read from
    ``HKLM\\SOFTWARE\\...\\Winlogon`` — pass it explicitly for the byte-based
    path (the SOFTWARE hive may be downloaded/parsed separately there). The
    inline ``RemoteRegistry`` backend already resolves this itself (it reads
    SOFTWARE in the same session and calls ``security.set_default_user(...)``
    before handing back the object), so a caller feeding an inline-sourced
    object may omit it.
    """
    try:
        from pypykatz.registry.security.common import (  # type: ignore[import-untyped]
            LSASecret as _SyncLSASecret,
            LSASecretASPNET as _SyncLSASecretASPNET,
            LSASecretDPAPI as _SyncLSASecretDPAPI,
            LSASecretDefaultPassword as _SyncLSASecretDefaultPassword,
            LSASecretMachineAccount as _SyncLSASecretMachineAccount,
            LSASecretService as _SyncLSASecretService,
        )
    except ImportError as exc:
        raise SecretsParserError(
            "pypykatz is not installed. Run 'adscan install' to install dependencies."
        ) from exc

    # The inline/live backend's SECURITY.get_secrets() (pypykatz asecurity.py)
    # creates its cached_secrets from a SEPARATE async class hierarchy
    # (acommon) — see the landmine note in the docstring above. Fall back to
    # the sync-only classes (tuple of just the sync class) if a pypykatz
    # version ever drops acommon, so this stays forward-compatible rather
    # than hard-failing.
    try:
        from pypykatz.registry.security.acommon import (  # type: ignore[import-untyped]
            LSASecret as _AsyncLSASecret,
            LSASecretASPNET as _AsyncLSASecretASPNET,
            LSASecretDPAPI as _AsyncLSASecretDPAPI,
            LSASecretDefaultPassword as _AsyncLSASecretDefaultPassword,
            LSASecretMachineAccount as _AsyncLSASecretMachineAccount,
            LSASecretService as _AsyncLSASecretService,
        )
    except ImportError:
        _AsyncLSASecret = _SyncLSASecret
        _AsyncLSASecretASPNET = _SyncLSASecretASPNET
        _AsyncLSASecretDPAPI = _SyncLSASecretDPAPI
        _AsyncLSASecretDefaultPassword = _SyncLSASecretDefaultPassword
        _AsyncLSASecretMachineAccount = _SyncLSASecretMachineAccount
        _AsyncLSASecretService = _SyncLSASecretService

    LSASecret = (_SyncLSASecret, _AsyncLSASecret)
    LSASecretASPNET = (_SyncLSASecretASPNET, _AsyncLSASecretASPNET)
    LSASecretDPAPI = (_SyncLSASecretDPAPI, _AsyncLSASecretDPAPI)
    LSASecretDefaultPassword = (_SyncLSASecretDefaultPassword, _AsyncLSASecretDefaultPassword)
    LSASecretMachineAccount = (_SyncLSASecretMachineAccount, _AsyncLSASecretMachineAccount)
    LSASecretService = (_SyncLSASecretService, _AsyncLSASecretService)

    machine_nt_hash: str | None = None
    machine_raw: bytes | None = None
    machine_kerberos_pw: bytes | None = None
    dpapi_machine: bytes | None = None
    dpapi_user: bytes | None = None
    dcc_hashes: list[str] = []
    service_secrets: dict[str, str] = {}
    service_secrets_raw: dict[str, bytes] = {}
    service_secret_owners: dict[str, str] = {}
    security_questions: dict[str, list[dict]] = {}
    raw_secrets: list[dict] = []

    if security_obj is None:
        print_info_verbose("[secrets_parser] SECURITY section is empty after parsing")
        return LSASecrets(
            machine_account_nt_hash=None,
            machine_account_password_raw=None,
        )

    for secret in security_obj.cached_secrets:
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
                # Service Control Manager cached credentials. The key name is a
                # SERVICE identifier, never an account name, and the payload is
                # not always a string: a ``_SC_GMSA_*`` key holds a binary
                # managed-password blob that only survives as raw bytes. Keep
                # both, and let the attribution layer decide what each one is.
                # History entries are skipped so the old password never
                # overwrites the current one under the same key.
                is_history = bool(getattr(secret, "history", False))
                svc_key = str(secret.key_name or "")
                if not is_history or svc_key not in service_secrets:
                    svc_secret = secret.secret or ""
                    service_secrets[svc_key] = str(svc_secret)
                    svc_raw = getattr(secret, "raw_secret", None)
                    if isinstance(svc_raw, (bytes, bytearray)) and svc_raw:
                        service_secrets_raw[svc_key] = bytes(svc_raw)
                    svc_owner = str(getattr(secret, "username", "") or "").strip()
                    if svc_owner and svc_owner.upper() != "UNKNOWN":
                        service_secret_owners[svc_key] = svc_owner
            elif isinstance(secret, LSASecretDefaultPassword):
                # AutoLogon / DefaultPassword LSA secret.
                # Use the actual owner username when available (read from
                # HKLM\SOFTWARE\...\Winlogon\DefaultUserName — same lookup
                # impacket performs via getDefaultLoginAccount()).  Falls back
                # to the raw key name when the Winlogon query was not possible.
                #
                # The inline RemoteRegistry backend already resolves the
                # SOFTWARE hive's DefaultUserName in the same session and
                # calls ``security.set_default_user(...)``, which stamps
                # ``secret.username`` directly on the object — honor that
                # self-attribution when the caller did not pass an explicit
                # ``winlogon_default_user`` (the byte-based path never sets
                # ``secret.username``, so this is a no-op there).
                #
                # pypykatz's OWN process_secret() unconditionally stamps
                # ``self.username = "UNKNOWN"`` as its own unresolved
                # placeholder (a TODO stub, same convention as
                # LSASecretService below) — that is NOT a real attribution,
                # so it must be excluded the same way the Service branch
                # above excludes it, or a DefaultPassword secret whose owner
                # was never resolved (SOFTWARE's DefaultUserName absent) gets
                # mis-filed under the literal key "UNKNOWN" instead of
                # falling through to the key-name fallback.
                self_attributed_user = str(getattr(secret, "username", "") or "").strip()
                if self_attributed_user.upper() == "UNKNOWN":
                    self_attributed_user = ""
                effective_default_user = winlogon_default_user or self_attributed_user or None
                is_history = bool(getattr(secret, "history", False))
                if is_history and effective_default_user:
                    # History entry — suppress when we already know the real owner.
                    # The old password belongs to the same user but is expired/stale.
                    # Without suppression it would land in service_secrets under the
                    # raw key "DEFAULTPASSWORD" and be persisted as a wrong-username
                    # credential after the attributed current entry.
                    pass
                else:
                    svc_key = (
                        effective_default_user
                        if (effective_default_user and not is_history)
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

    for dcc in security_obj.dcc_hashes:
        try:
            dcc_hashes.append(str(dcc))
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[secrets_parser] error processing DCC hash: {exc}")

    print_info_debug(
        f"[secrets_parser] map_security_secrets: machine_acc={'yes' if machine_nt_hash else 'no'}, "
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
        service_secrets_raw=service_secrets_raw,
        service_secret_owners=service_secret_owners,
        security_questions=security_questions,
        raw_secrets=raw_secrets,
    )


def _sync_parse_lsa_secrets(
    security_bytes: bytes,
    system_bytes: bytes,
    *,
    winlogon_default_user: str | None = None,
) -> LSASecrets:
    """Synchronously parse SECURITY hive for LSA secrets using pypykatz library.

    Thin wrapper: parses bytes into a pypykatz SECURITY object, then delegates
    the object-to-model mapping to :func:`map_security_secrets` (the shared
    SSOT also used by the inline backend).
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
            security_data=security_bytes,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        raise SecretsParserError(f"pypykatz SECURITY parse error: {exc}") from exc

    return map_security_secrets(registry.security, winlogon_default_user=winlogon_default_user)


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
