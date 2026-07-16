"""Credential service for credential-related operations.

This module provides services for credential verification, roasting attacks
(Kerberoast, ASREPRoast), and password spraying.
"""

from typing import Callable, Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import asyncio
import subprocess
import os
import logging
import re
import shlex

from adscan_internal import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.services.base_service import BaseService
from adscan_internal.core import CredentialFoundEvent
from adscan_internal.execution_outcomes import output_has_timeout_marker
from adscan_internal.integrations.impacket.parsers import (
    extract_kerberoast_candidate_users,
    parse_kerberoast_output,
)
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)


logger = logging.getLogger(__name__)

_NETEXEC_NEGATIVE_AUTH_LINE_RE = re.compile(
    r"\[-\]\s+(?P<principal>[^\s]+(?:\\|/)[^:\s]+):",
    re.IGNORECASE,
)

CommandExecutor = Callable[[str, int], subprocess.CompletedProcess[str] | None]


def _default_executor(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Execute a shell command using the shared command runner.

    Args:
        command: Command string to execute.
        timeout: Timeout in seconds.

    Returns:
        subprocess.CompletedProcess instance.
    """
    use_clean_env = command_string_needs_clean_env(command)
    cmd_env = get_clean_env_for_compilation() if use_clean_env else None
    return default_runner.run(
        CommandSpec(
            command=command,
            timeout=timeout,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
            env=cmd_env,
        )
    )


def _ensure_completed_process(
    result: subprocess.CompletedProcess[str] | None, *, operation: str
) -> subprocess.CompletedProcess[str]:
    """Return a completed process or raise a descriptive error.

    Some command runners may return ``None`` when execution fails before a
    process result is available (for example, pre-execution errors in wrappers).
    Service methods expect a process-like object and should fail with a clear
    domain-specific message rather than ``AttributeError`` on ``stdout``.
    """
    if not isinstance(result, subprocess.CompletedProcess):
        raise RuntimeError(f"{operation} command returned no process result.")
    return result


async def _diagnose_kdc_unreachable(*, kdc_ip: str, original_error: str) -> str:
    """Translate a Kerberos transport failure into an actionable diagnosis.

    Runs a 2-second native TCP probe to ``kdc_ip:88`` and maps the three
    probe outcomes to operator-facing language. Replaces the historic
    NetExec LDAP fallback, which gave a different protocol's answer when
    Kerberos was actually unreachable — a silent inconsistency this
    message removes. Never raises.
    """
    from adscan_internal.services.network_probe_service import tcp_probe

    if not kdc_ip:
        return f"Kerberos transport error (KDC address not set): {original_error}"

    probe = await tcp_probe(kdc_ip, 88, timeout=2.0)
    if probe.status == "filtered":
        return (
            f"Kerberos KDC unreachable: TCP/88 on {kdc_ip} is filtered "
            "(no response). Verify network access from this host before "
            "retrying — credentials cannot be validated without KDC access."
        )
    if probe.status == "closed":
        return (
            f"Kerberos KDC unreachable: TCP/88 on {kdc_ip} actively refused "
            "the connection. The KDC service may be stopped on the DC."
        )
    return f"Kerberos transport error (TCP/88 reachable on {kdc_ip}): {original_error}"


def _walk_exc_chain(exc: BaseException, *, max_depth: int = 10) -> list[BaseException]:
    """Return the exception and its ``__cause__`` / ``__context__`` chain.

    Bounded to ``max_depth`` to guard against cyclic chains. Used to classify a
    bind failure (definitive credential rejection vs transport/policy) across
    the whole nested chain badldap/aiosmb may raise.
    """
    seen: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and len(seen) < max_depth:
        if current in seen:
            break
        seen.append(current)
        current = current.__cause__ or current.__context__
    return seen


class CredentialStatus(str, Enum):
    """Status of credential verification."""

    VALID = "valid"
    INVALID = "invalid"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"
    PASSWORD_EXPIRED = "password_expired"
    PASSWORD_MUST_CHANGE = "password_must_change"
    USER_NOT_FOUND = "user_not_found"
    ACCOUNT_RESTRICTION = "account_restriction"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class CredentialVerificationResult:
    """Result of credential verification.

    Attributes:
        status: Verification status
        username: Username tested
        domain: Domain tested against
        credential_type: Type of credential (password or hash)
        error_message: Error message if verification failed
        is_admin: Whether account has admin privileges (if detected)
        raw_output: Raw tool output when available (not serialized for security)
        protocol_used: Which transport actually produced the verdict
            ("kerberos", "ntlm-ldap", "ntlm-smb"). Lets the caller render an
            accurate Protocol label instead of a hardcoded one.
    """

    status: CredentialStatus
    username: str
    domain: str
    credential_type: str = "password"
    error_message: Optional[str] = None
    is_admin: bool = False
    protocol_used: str = "kerberos"
    # Raw command output is kept for in-process consumers (e.g. CLI) but is
    # intentionally excluded from serialized representations to avoid leaking
    # potentially sensitive information.
    raw_output: Optional[str] = None

    def is_valid(self) -> bool:
        """Check if credentials are valid."""
        return self.status == CredentialStatus.VALID

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "username": self.username,
            "domain": self.domain,
            "credential_type": self.credential_type,
            "error_message": self.error_message,
            "is_admin": self.is_admin,
        }


@dataclass
class RoastingResult:
    """Result of a roasting attack (Kerberoast/ASREPRoast).

    Attributes:
        attack_type: Type of attack (kerberoast or asreproast)
        domain: Target domain
        hashes_found: Number of hashes extracted
        roastable_users: List of roastable usernames
        output_file: Path to output file with hashes
        success: Whether attack succeeded
        error_message: Error message if attack failed
    """

    attack_type: str  # "kerberoast" or "asreproast"
    domain: str
    hashes_found: int = 0
    roastable_users: List[str] = None
    output_file: Optional[str] = None
    success: bool = False
    error_message: Optional[str] = None

    def __post_init__(self):
        """Initialize roastable_users if None."""
        if self.roastable_users is None:
            self.roastable_users = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "attack_type": self.attack_type,
            "domain": self.domain,
            "hashes_found": self.hashes_found,
            "roastable_users": self.roastable_users,
            "output_file": self.output_file,
            "success": self.success,
            "error_message": self.error_message,
        }


@dataclass
class PasswordChangeResult:
    """Result of a NetExec password-change operation."""

    success: bool
    username: str
    domain: str
    error_message: Optional[str] = None
    raw_output: Optional[str] = None


class CredentialService(BaseService):
    """Service for credential operations.

    This service encapsulates credential-related operations including:
    - Credential verification against domain controllers
    - Kerberoast attacks
    - ASREPRoast attacks
    - Password spraying
    """

    # ------------------------------------------------------------------ #
    # Native Kerberos verification                                         #
    # ------------------------------------------------------------------ #

    async def _verify_via_kerberos(
        self,
        *,
        domain: str,
        kdc_ip: str,
        username: str,
        credential: str,
        credential_type: str,
        posture_snapshot: Any = None,
    ) -> "CredentialVerificationResult":
        """Verify a domain credential by requesting a Kerberos TGT via kerbad.

        Returns a :class:`CredentialVerificationResult` in the same shape as
        the netexec path so the caller can use either without changes.

        Side-effect: on success the ccache bytes are attached to the result via
        ``result.raw_output`` field (bytes, not str) so the caller can persist
        the ticket immediately without an extra round-trip.

        No-verdict recovery: when the KDC is unreachable (port 88 filtered /
        transport error) Kerberos reaches NO verdict at all. In that case ONLY —
        never when Kerberos returned a definitive auth answer — and only for an
        NTLM-native secret (password / NT hash), we attempt ONE NTLM bind
        (LDAP/389 first, SMB/445 backstop) to validate the credential without
        the KDC. This is the recovery the historic, deleted NetExec fallback
        botched: that fallback fired on EVERY failure and second-guessed real
        Kerberos verdicts. This one fires only on the no-verdict case. See
        :meth:`_verify_via_ntlm`.

        ``posture_snapshot`` (a ``DomainPosture``) gates the NTLM fallback: it
        is skipped when ``NTLM_AUTHENTICATION`` is known-DISABLED, and threaded
        into the transport configs for auth-plan pruning.
        """
        from adscan_internal.services.kerberos_transport import (
            KerberosAuthError,
            KerberosClockSkewError,
            KerberosConfig,
            KerberosEtypeError,
            KerberosPrincipalError,
            KerberosTransportError,
            get_tgt,
        )

        nt_hash = credential if credential_type == "hash" else None
        password = credential if credential_type == "password" else None

        cfg = KerberosConfig(
            domain=domain,
            kdc_ip=kdc_ip,
            username=username,
            password=password,
            nt_hash=nt_hash,
        )

        def _ok(ccache: bytes) -> "CredentialVerificationResult":
            r = CredentialVerificationResult(
                status=CredentialStatus.VALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
            )
            # Attach ccache bytes so the caller can persist the ticket without
            # an extra AS-REQ.  raw_output normally holds str but bytes here is
            # intentional and documented — callers check isinstance before use.
            r.raw_output = ccache  # type: ignore[assignment]
            return r

        def _fail(status: CredentialStatus, msg: str) -> "CredentialVerificationResult":
            return CredentialVerificationResult(
                status=status,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message=msg,
            )

        try:
            ccache = await get_tgt(cfg)
            return _ok(ccache)

        except KerberosEtypeError:
            # RC4 rejected (AES-only KDC) — retry with AES etypes only.
            from dataclasses import replace as _dc_replace
            cfg_aes = _dc_replace(cfg, etypes=[18, 17])
            try:
                ccache = await get_tgt(cfg_aes)
                return _ok(ccache)
            except KerberosAuthError:
                return _fail(CredentialStatus.INVALID, "Invalid credentials (AES-only KDC)")
            except KerberosPrincipalError:
                return _fail(CredentialStatus.USER_NOT_FOUND, "User not found")
            except KerberosTransportError as exc:
                # No-verdict transport failure on the AES retry — same recovery
                # as the outer branch: try NTLM (LDAP then SMB) before giving up.
                ntlm_result = await self._verify_via_ntlm(
                    domain=domain,
                    target_ip=kdc_ip,
                    username=username,
                    credential=credential,
                    credential_type=credential_type,
                    posture_snapshot=posture_snapshot,
                )
                if ntlm_result is not None:
                    return ntlm_result
                diagnosis = await _diagnose_kdc_unreachable(
                    kdc_ip=kdc_ip, original_error=str(exc)
                )
                return _fail(CredentialStatus.ERROR, diagnosis)

        except KerberosPrincipalError:
            return _fail(CredentialStatus.USER_NOT_FOUND, "User not found")

        except KerberosAuthError as exc:
            # Inspect the original kerbad error code to distinguish sub-states.
            # KDC_ERR_CLIENT_REVOKED (0x12=18) covers locked + disabled accounts;
            # we disambiguate with a quick LDAP read of userAccountControl.
            # KDC_ERR_KEY_EXPIRED (0x17=23) = password must change.
            original = getattr(exc, "__cause__", exc)
            try:
                from kerbad.protocol.errors import KerberosErrorCode  # noqa: PLC0415
                code = getattr(original, "errorcode", None)
                if code == KerberosErrorCode.KDC_ERR_KEY_EXPIRED:
                    return _fail(
                        CredentialStatus.PASSWORD_MUST_CHANGE,
                        "Password must be changed before logon",
                    )
                if code == KerberosErrorCode.KDC_ERR_CLIENT_REVOKED:
                    # Distinguish locked vs disabled via LDAP userAccountControl.
                    uac_status = await self._ldap_get_account_status(
                        domain=domain, kdc_ip=kdc_ip,
                        username=username, password=password, nt_hash=nt_hash,
                    )
                    return _fail(uac_status, uac_status.value.replace("_", " ").capitalize())
            except Exception:  # noqa: BLE001
                pass
            return _fail(CredentialStatus.INVALID, "Invalid credentials")

        except KerberosClockSkewError:
            # Clock skew is a transport problem, not a credential problem.
            # Signal ERROR so the caller can fall back to netexec (which has its
            # own clock-sync logic) or prompt for manual sync.
            return _fail(CredentialStatus.ERROR, "Clock skew too large — sync clocks and retry")

        except KerberosTransportError as exc:
            # Port 88 unreachable, DNS failure, etc. This is the NO-VERDICT
            # case: Kerberos never reached the credential check, so trying NTLM
            # here does NOT second-guess a real Kerberos answer (unlike the
            # deleted NetExec fallback, which fired on every failure). When the
            # secret is NTLM-native and a non-Kerberos auth port is reachable,
            # one NTLM bind validates it without the KDC.
            ntlm_result = await self._verify_via_ntlm(
                domain=domain,
                target_ip=kdc_ip,
                username=username,
                credential=credential,
                credential_type=credential_type,
                posture_snapshot=posture_snapshot,
            )
            if ntlm_result is not None:
                return ntlm_result

            # NTLM was disabled, not applicable, or also unreachable. Keep the
            # precise KDC diagnosis ("filtered" vs "closed" vs reachable-but-
            # failing) — it is the correct verdict when no transport could
            # validate the credential.
            diagnosis = await _diagnose_kdc_unreachable(
                kdc_ip=kdc_ip, original_error=str(exc)
            )
            return _fail(CredentialStatus.ERROR, diagnosis)

        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return _fail(CredentialStatus.ERROR, str(exc))

    async def _verify_via_ntlm(
        self,
        *,
        domain: str,
        target_ip: str,
        username: str,
        credential: str,
        credential_type: str,
        posture_snapshot: Any = None,
    ) -> "Optional[CredentialVerificationResult]":
        """Validate an NTLM-native credential via a single NTLM bind.

        Recovery path for the KDC-unreachable / no-verdict case: tries LDAP/389
        NTLM first (cheapest, most permissive), then SMB/445 as a backstop. A
        successful bind on either → :class:`CredentialStatus.VALID`. An NTLM
        transport that is itself definitive about the credential (the bind
        completed and the server rejected the password) → ``INVALID``; that is
        a real NTLM verdict and is trusted (it is no longer the no-verdict
        case). When NTLM cannot be used at all, returns ``None`` so the caller
        keeps the precise KDC diagnosis:

        - the secret is not NTLM-native (a ccache / AES key / SPN-only artifact);
        - ``NTLM_AUTHENTICATION`` posture is known-DISABLED;
        - both NTLM transports were also unreachable (no port answered).

        Never raises — any unexpected error is captured and returns ``None``.

        Args:
            domain: Target domain the credential belongs to.
            target_ip: DC / host to bind against (LDAP 389, SMB 445).
            username: sAMAccountName to authenticate as.
            credential: The secret (password or NT hash).
            credential_type: ``"password"`` or ``"hash"``.
            posture_snapshot: ``DomainPosture`` for the target domain; gates
                NTLM and is threaded into the transport configs for pruning.

        Returns:
            A VALID/INVALID result when NTLM produced a verdict; ``None`` when
            NTLM could not be attempted or was also unreachable.
        """
        # NTLM bind only accepts a password or an NT hash — never a ccache, an
        # AES key, or any capability-bearing artifact. AES-only credentials are
        # not NTLM-native (NTLM derives from the NT hash, not the AES key).
        if credential_type not in ("password", "hash"):
            return None

        # Posture gate: do not spend an NTLM bind when the DC is known to reject
        # NTLM. A known-DISABLED verdict is the only reason to skip — UNKNOWN /
        # ENABLED both allow the attempt (observe, do not infer).
        if self._ntlm_known_disabled(posture_snapshot):
            print_info_debug(
                "[verify] NTLM fallback skipped: NTLM_AUTHENTICATION is "
                "known-disabled for this domain."
            )
            return None

        nt_hash = credential if credential_type == "hash" else None
        password = credential if credential_type == "password" else None

        ldap_result = await self._verify_via_ntlm_ldap(
            domain=domain,
            target_ip=target_ip,
            username=username,
            password=password,
            nt_hash=nt_hash,
            credential_type=credential_type,
            posture_snapshot=posture_snapshot,
        )
        if ldap_result is not None:
            return ldap_result

        return await self._verify_via_ntlm_smb(
            domain=domain,
            target_ip=target_ip,
            username=username,
            password=password,
            nt_hash=nt_hash,
            credential_type=credential_type,
            posture_snapshot=posture_snapshot,
        )

    @staticmethod
    def _ntlm_known_disabled(posture_snapshot: Any) -> bool:
        """Return True only when NTLM_AUTHENTICATION is recorded DISABLED HIGH.

        Observe-don't-infer: an UNKNOWN / LOW-confidence record never blocks the
        attempt. Never raises.
        """
        if posture_snapshot is None:
            return False
        try:
            from adscan_internal.services.domain_posture import (
                ConstraintCategory,
                SignalConfidence,
                TriState,
            )

            state = posture_snapshot.get(ConstraintCategory.NTLM_AUTHENTICATION)
            return bool(
                state
                and state.state is TriState.DISABLED
                and state.confidence is SignalConfidence.HIGH
            )
        except Exception:  # noqa: BLE001
            return False

    async def _verify_via_ntlm_ldap(
        self,
        *,
        domain: str,
        target_ip: str,
        username: str,
        password: Optional[str],
        nt_hash: Optional[str],
        credential_type: str,
        posture_snapshot: Any = None,
    ) -> "Optional[CredentialVerificationResult]":
        """Attempt one NTLM LDAP bind. See :meth:`_verify_via_ntlm` for contract."""
        from adscan_internal.services import ldap_transport_service as _ldap_mod

        try:
            # ADscanLDAPConfig has no dedicated nt_hash field: an NT hash placed
            # in ``password`` is auto-routed to the ``ntlm-nt`` (pass-the-hash)
            # auth kind by ``_is_nt_hash`` inside the transport.
            cfg = _ldap_mod.ADscanLDAPConfig(
                domain=domain,
                dc_ip=target_ip,
                use_ldaps=True,  # fallback downgrades to LDAP/389 automatically
                use_kerberos=False,
                username=username,
                password=(nt_hash or password or ""),
                posture_snapshot=posture_snapshot,
            )
            result = await _ldap_mod.async_connect_with_ldap_fallback(
                cfg, bind_only=True
            )
            client = result.client
            try:
                if client is not None:
                    await client.disconnect()
            except Exception:  # noqa: BLE001
                pass
            print_info_debug(
                "[verify] credential validated via NTLM LDAP bind "
                "(Kerberos KDC was unreachable)."
            )
            return CredentialVerificationResult(
                status=CredentialStatus.VALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message=(
                    "Validated via NTLM (LDAP); Kerberos KDC unreachable, no TGT minted."
                ),
                protocol_used="ntlm-ldap",
            )
        except Exception as exc:  # noqa: BLE001
            # Transport failure (LDAP also unreachable) → no verdict here; let
            # the SMB backstop try. A definitive bind rejection → NTLM verdict.
            if _ldap_mod.is_ldaps_transport_failure(exc):
                print_info_debug(
                    f"[verify] NTLM LDAP bind unreachable: {type(exc).__name__}; "
                    "trying SMB backstop."
                )
                return None
            if self._is_ntlm_bind_rejection(exc):
                print_info_debug(
                    "[verify] NTLM LDAP bind rejected the credential — "
                    "definitive INVALID verdict."
                )
                return CredentialVerificationResult(
                    status=CredentialStatus.INVALID,
                    username=username,
                    domain=domain,
                    credential_type=credential_type,
                    error_message="Invalid credentials (validated via NTLM/LDAP)",
                    protocol_used="ntlm-ldap",
                )
            # Anything we cannot classify (e.g. strongerAuthRequired / channel
            # binding) is not a credential verdict — fall through to SMB.
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[verify] NTLM LDAP bind inconclusive: {type(exc).__name__}: {exc}; "
                "trying SMB backstop."
            )
            return None

    async def _verify_via_ntlm_smb(
        self,
        *,
        domain: str,
        target_ip: str,
        username: str,
        password: Optional[str],
        nt_hash: Optional[str],
        credential_type: str,
        posture_snapshot: Any = None,
    ) -> "Optional[CredentialVerificationResult]":
        """Attempt one NTLM SMB bind (445). See :meth:`_verify_via_ntlm`."""
        try:
            from adscan_internal.services.smb_transport import (
                SMBAuthError,
                SMBConfig,
                smb_machine_for,
            )

            cfg = SMBConfig(
                target_ip=target_ip,
                domain=domain,
                auth_domain=domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
                use_kerberos=False,
                posture_snapshot=posture_snapshot,
            )
            async with smb_machine_for(cfg):
                # Connecting + logging in is the verification; reaching here means
                # the server accepted the credential.
                pass
            print_info_debug(
                "[verify] credential validated via NTLM SMB bind "
                "(Kerberos KDC was unreachable)."
            )
            return CredentialVerificationResult(
                status=CredentialStatus.VALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message=(
                    "Validated via NTLM (SMB); Kerberos KDC unreachable, no TGT minted."
                ),
                protocol_used="ntlm-smb",
            )
        except SMBAuthError:
            print_info_debug(
                "[verify] NTLM SMB bind rejected the credential — "
                "definitive INVALID verdict."
            )
            return CredentialVerificationResult(
                status=CredentialStatus.INVALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Invalid credentials (validated via NTLM/SMB)",
                protocol_used="ntlm-smb",
            )
        except Exception as exc:  # noqa: BLE001
            # SMB also unreachable / inconclusive → no verdict; the caller keeps
            # the precise KDC-filtered diagnosis.
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[verify] NTLM SMB bind unreachable/inconclusive: "
                f"{type(exc).__name__}: {exc}."
            )
            return None

    @staticmethod
    def _is_ntlm_bind_rejection(exc: BaseException) -> bool:
        """Return whether an LDAP exception is a definitive NTLM credential rejection.

        A completed bind that the DC rejected with ``invalidCredentials`` /
        ``SEC_E_LOGON_DENIED`` (the badldap shapes for a bad NTLM password) is a
        real verdict. ``strongerAuthRequired`` / ``SEC_E_BAD_BINDINGS`` are
        signing/channel-binding policy, NOT a credential verdict, so they are
        excluded — those mean "this transport could not carry the bind", which
        is inconclusive, not INVALID.
        """
        text = " ".join(
            f"{type(c).__name__}: {c}".lower()
            for c in _walk_exc_chain(exc)
        )
        if "strongerauthrequired" in text or "sec_e_bad_bindings" in text:
            return False
        return "invalidcredentials" in text or "sec_e_logon_denied" in text

    async def _ldap_get_account_status(
        self,
        *,
        domain: str,
        kdc_ip: str,
        username: str,
        password: Optional[str],
        nt_hash: Optional[str],
    ) -> "CredentialStatus":
        """Return ACCOUNT_LOCKED or ACCOUNT_DISABLED by reading userAccountControl via LDAP.

        Uses an anonymous LDAP bind (no credentials needed for this attribute in
        most AD configs) to avoid triggering another bad-password count.
        Falls back to ACCOUNT_LOCKED when the attribute is unreadable.
        """
        try:
            from adscan_internal.services.ldap_transport_service import (
                ADscanLDAPConfig,
                ADscanLDAPConnection,
            )

            cfg = ADscanLDAPConfig(
                domain=domain,
                dc_ip=kdc_ip,
                use_ldaps=True,
                use_kerberos=False,
                username="",
                password="",
            )
            with ADscanLDAPConnection(cfg) as conn:
                conn.search(
                    search_base=conn.domain_dn,
                    search_filter=f"(sAMAccountName={username})",
                    attributes=["userAccountControl"],
                )
                if conn.entries:
                    uac_vals = (
                        conn.entries[0].entry_attributes_as_dict.get("userAccountControl") or []
                    )
                    uac = int(uac_vals[0]) if uac_vals else 0
                    # Bit 4 (0x10) = LOCKOUT, bit 1 (0x2) = ACCOUNTDISABLE
                    if uac & 0x10:
                        return CredentialStatus.ACCOUNT_LOCKED
                    if uac & 0x2:
                        return CredentialStatus.ACCOUNT_DISABLED
        except Exception:  # noqa: BLE001
            pass
        return CredentialStatus.ACCOUNT_LOCKED  # safe default

    def _verify_via_kerberos_sync(
        self,
        *,
        domain: str,
        kdc_ip: str,
        username: str,
        credential: str,
        credential_type: str,
        posture_snapshot: Any = None,
    ) -> "CredentialVerificationResult":
        """Sync wrapper for :meth:`_verify_via_kerberos`.

        Detects whether an event loop is already running (lab runner, test
        harness) and dispatches to a worker thread to avoid nested-loop errors.

        ``posture_snapshot`` is forwarded to gate the KDC-unreachable NTLM
        fallback (skipped when NTLM is known-disabled).
        """
        import concurrent.futures

        coro = self._verify_via_kerberos(
            domain=domain,
            kdc_ip=kdc_ip,
            username=username,
            credential=credential,
            credential_type=credential_type,
            posture_snapshot=posture_snapshot,
        )
        try:
            asyncio.get_running_loop()
            in_loop = True
        except RuntimeError:
            in_loop = False

        if in_loop:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(lambda: asyncio.run(coro)).result()
        return asyncio.run(coro)


    def _parse_password_change_output(
        self,
        *,
        output: str,
        username: str,
        domain: str,
    ) -> PasswordChangeResult:
        """Parse NetExec ``change-password`` output."""
        if "Successfully changed password for" in output:
            return PasswordChangeResult(
                success=True,
                username=username,
                domain=domain,
            )

        if "STATUS_PASSWORD_MUST_CHANGE" in output:
            return PasswordChangeResult(
                success=False,
                username=username,
                domain=domain,
                error_message=(
                    "Current password is correct but must be changed before logon"
                ),
            )

        if "STATUS_LOGON_FAILURE" in output or "KDC_ERR_PREAUTH_FAILED" in output:
            return PasswordChangeResult(
                success=False,
                username=username,
                domain=domain,
                error_message="Current password was rejected during password change",
            )

        return PasswordChangeResult(
            success=False,
            username=username,
            domain=domain,
            error_message="Unknown password change result",
        )

    def change_password_with_samr(
        self,
        *,
        domain: str,
        username: str,
        old_password: str,
        new_password: str,
        pdc_host: str,
        pdc_ip: Optional[str] = None,
        timeout: int = 60,
    ) -> "PasswordChangeResult":
        """Change the user's own expired password via SAMR SamrChangePasswordUser.

        This is the native path for STATUS_PASSWORD_MUST_CHANGE: the user
        authenticates with their old (expired) password and sets a new one via
        ``hSamrUnicodeChangePasswordUser2`` (MS-SAMR), which takes old+new with
        NO prior authenticated bind.

        SAMR is the ONLY viable mechanism here: a ``MUST_CHANGE`` account cannot
        perform an authenticated LDAP bind, so no LDAP ``unicodePwd`` rung is
        possible (an earlier docstring claimed an LDAPS fallback that the code
        never implemented — there is none, by protocol). SAMR over RPC is itself
        confidential (PKT_PRIVACY). Two transports are attempted: authenticated
        ncacn_np, then ncacn_ip_tcp anonymous on a must-change rejection.
        """
        import asyncio as _asyncio
        import concurrent.futures as _cf
        from adscan_internal.services.smb_transport import SMBConfig
        from adscan_internal.services.exploitation._samr_backend import (
            samr_change_password,
        )

        connect_ip = pdc_ip or pdc_host
        sam_user = username.split("@")[0] if "@" in username else username

        # Authenticated ncacn_np session built from the operator's old (expired)
        # password. The shared SAMR backend owns the two-stage transport:
        # ncacn_np auth first, ncacn_ip_tcp anonymous on a must-change rejection
        # (which bypasses RestrictNullSessAccess on hardened DCs).
        auth_config = SMBConfig(
            target_ip=connect_ip,
            target_hostname=connect_ip,
            domain=domain,
            username=username,
            password=old_password,
            auth_domain=domain,
            use_kerberos=False,
            kdc_ip=connect_ip,
            timeout=timeout,
        )

        async def _do_samr_unicode_change() -> bool:
            return await samr_change_password(
                auth_config=auth_config,
                connect_ip=connect_ip,
                sam_user=sam_user,
                old_password=old_password,
                new_password=new_password,
            )

        try:
            try:
                ok = _asyncio.run(_do_samr_unicode_change())
            except RuntimeError:
                with _cf.ThreadPoolExecutor(max_workers=1) as pool:
                    ok = pool.submit(_asyncio.run, _do_samr_unicode_change()).result(timeout=timeout)
        except Exception as exc:
            from adscan_core import telemetry
            telemetry.capture_exception(exc)
            return PasswordChangeResult(
                success=False,
                username=username,
                domain=domain,
                error_message=f"SAMR change_user_password exception: {exc}",
            )

        return PasswordChangeResult(success=ok, username=username, domain=domain)

    def kerberoast(
        self,
        domain: str,
        username: str,
        password: str,
        getuserspns_path: str,
        auth_string: str,
        output_file: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
    ) -> RoastingResult:
        """Perform Kerberoast attack.

        Args:
            domain: Target domain
            username: Authentication username
            password: Authentication password
            getuserspns_path: Path to GetUserSPNs.py (Impacket)
            auth_string: Pre-built auth string for Impacket
            output_file: Path to output file for hashes
            scan_id: Optional scan ID
            timeout: Command timeout in seconds

        Returns:
            RoastingResult with attack results
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="kerberoast",
            progress=0.0,
            message=f"Starting Kerberoast attack on {domain}",
        )

        self.logger.info(f"Executing Kerberoast attack on domain: {domain}")

        # Build command
        command = (
            f"{shlex.quote(getuserspns_path)} -request {auth_string} "
            f"-target-domain {shlex.quote(domain)} -outputfile {shlex.quote(output_file)}"
        )

        self._emit_progress(
            scan_id=scan_id,
            phase="kerberoast",
            progress=0.3,
            message="Executing Kerberoast command",
        )

        try:
            exec_fn = executor or _default_executor
            result = _ensure_completed_process(
                exec_fn(command, timeout),
                operation="Kerberoast",
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="kerberoast",
                progress=0.7,
                message="Parsing Kerberoast results",
            )

            # Parse roastable users from stdout
            roastable_users = (
                extract_kerberoast_candidate_users(result.stdout or "")
                if result.stdout
                else []
            )

            # Count hashes in output file
            hashes_found = 0
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                    hashes_found = len(parse_kerberoast_output(f.read()))

            self._emit_progress(
                scan_id=scan_id,
                phase="kerberoast",
                progress=1.0,
                message=f"Kerberoast completed: {hashes_found} hash(es) found",
            )

            # Emit events for discovered credentials
            for user in roastable_users[:hashes_found]:
                self._emit_event(
                    CredentialFoundEvent(
                        scan_id=scan_id,
                        credential_type="kerberos_hash",
                        username=user,
                        domain=domain,
                        source="kerberoast",
                        is_admin=False,
                    )
                )

            self.logger.info(
                f"Kerberoast completed for {domain}: {hashes_found} hash(es), "
                f"{len(roastable_users)} roastable user(s)"
            )

            return RoastingResult(
                attack_type="kerberoast",
                domain=domain,
                hashes_found=hashes_found,
                roastable_users=roastable_users,
                output_file=output_file,
                success=True,
            )

        except subprocess.TimeoutExpired:
            self.logger.error(f"Kerberoast timed out for domain {domain}")
            self._emit_progress(
                scan_id=scan_id,
                phase="kerberoast",
                progress=1.0,
                message="Kerberoast timed out",
            )
            return RoastingResult(
                attack_type="kerberoast",
                domain=domain,
                success=False,
                error_message="Kerberoast timed out",
            )

        except Exception as e:
            self.logger.exception(f"Error during Kerberoast: {e}")
            self._emit_progress(
                scan_id=scan_id,
                phase="kerberoast",
                progress=1.0,
                message="Kerberoast failed",
            )
            return RoastingResult(
                attack_type="kerberoast",
                domain=domain,
                success=False,
                error_message=str(e),
            )

    def _is_ntlm_hash(self, credential: str) -> bool:
        """Check if credential is an NTLM hash.

        Args:
            credential: Credential to check

        Returns:
            True if NTLM hash, False otherwise
        """
        return len(credential) == 32 and all(
            c in "0123456789abcdef" for c in credential.lower()
        )

    def _parse_verification_output(
        self,
        output: str,
        username: str,
        domain: str,
        credential_type: str,
    ) -> CredentialVerificationResult:
        """Parse NetExec verification output.

        Args:
            output: Command output
            username: Username tested
            domain: Domain tested
            credential_type: Type of credential

        Returns:
            CredentialVerificationResult
        """
        # Check for various status codes
        if output_has_timeout_marker(output):
            return CredentialVerificationResult(
                status=CredentialStatus.TIMEOUT,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message=(
                    "NetExec command timed out. Verify VPN/network connectivity and retry."
                ),
            )

        if "STATUS_LOGON_FAILURE" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.INVALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Incorrect credentials",
            )

        if "STATUS_ACCOUNT_LOCKED_OUT" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.ACCOUNT_LOCKED,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Account locked out",
            )

        if "STATUS_ACCOUNT_DISABLED" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.ACCOUNT_DISABLED,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Account disabled",
            )

        if "STATUS_ACCOUNT_RESTRICTION" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.ACCOUNT_RESTRICTION,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Account restricted",
            )

        if "STATUS_PASSWORD_EXPIRED" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.PASSWORD_EXPIRED,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Password expired",
            )

        if "KDC_ERR_KEY_EXPIRED" in output or "STATUS_PASSWORD_MUST_CHANGE" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.PASSWORD_MUST_CHANGE,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Password must be changed before logon",
            )

        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.USER_NOT_FOUND,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="User not found",
            )

        if "KDC_ERR_PREAUTH_FAILED" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.INVALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Pre-authentication failed",
            )

        if self._contains_negative_auth_result(output, username, domain):
            return CredentialVerificationResult(
                status=CredentialStatus.INVALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Incorrect credentials",
            )

        # Check for success
        if "[+]" in output:
            is_admin = "(Pwn3d!)" in output
            return CredentialVerificationResult(
                status=CredentialStatus.VALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                is_admin=is_admin,
            )

        # Unknown status
        return CredentialVerificationResult(
            status=CredentialStatus.ERROR,
            username=username,
            domain=domain,
            credential_type=credential_type,
            error_message="Unknown verification result",
        )

    @staticmethod
    def _contains_negative_auth_result(output: str, username: str, domain: str) -> bool:
        """Return True when NetExec emitted a generic failed-auth line.

        NetExec often returns ``0`` even when LDAP/SMB auth fails, and for some
        protocols it emits only a generic ``[-] domain\\user:secret`` line
        without a more specific status code such as ``STATUS_LOGON_FAILURE``.
        Treat those lines as invalid credentials when they match the tested
        principal so the CLI does not downgrade them to an opaque error.
        """

        expected_principals = {
            f"{domain}\\{username}".lower(),
            f"{domain}/{username}".lower(),
            username.lower(),
        }
        for match in _NETEXEC_NEGATIVE_AUTH_LINE_RE.finditer(output):
            if match.group("principal").lower() in expected_principals:
                return True
        return False

    def execute_password_spraying(
        self,
        command: str,
        domain: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute password spraying command and parse results.

        Args:
            command: Full kerbrute command string to execute.
            domain: Target domain name.
            executor: Optional command executor. When not provided, uses default
                subprocess executor. The CLI layer should inject its own executor
                that routes through shell.run_command to ensure clean_env handling.
            scan_id: Optional scan ID for progress tracking.

        Returns:
            Dictionary with:
            - success: bool - Whether command executed successfully
            - found_credentials: bool - Whether any valid credentials were found
            - credentials: List[Dict[str, str]] - List of found credentials
                (each with 'username' and 'password')
            - returncode: int - Command return code
            - stdout: str - Command stdout (stripped of ANSI codes)
            - stderr: str - Command stderr (stripped of ANSI codes)
        """
        from adscan_internal.text_utils import strip_ansi_codes

        self._emit_progress(
            scan_id=scan_id,
            phase="password_spraying",
            progress=0.0,
            message=f"Executing password spraying on {domain}",
        )

        executor_func = executor or _default_executor
        credentials_found = []

        try:
            self.logger.info(
                f"Executing password spraying command on {domain}",
                extra={"command": command, "domain": domain},
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=0.5,
                message="Running kerbrute command...",
            )

            # Execute command (no timeout for spraying - can take a long time)
            completed = executor_func(command, timeout=None)

            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=0.8,
                message="Parsing results...",
            )

            # Process output
            raw_output = completed.stdout or ""
            raw_stderr = completed.stderr or ""
            output = strip_ansi_codes(raw_output)
            stderr_output = strip_ansi_codes(raw_stderr)
            output_lines = output.splitlines() if output else []

            # Parse valid logins from output
            for line in output_lines:
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                if "VALID LOGIN" in line_stripped:
                    try:
                        creds = line_stripped.split("VALID LOGIN:")[1].strip()
                        user_domain, password = creds.split(":")
                        username = user_domain.split("@")[0]
                        credentials_found.append(
                            {"username": username, "password": password}
                        )
                        self.logger.info(
                            f"Found valid credentials: {username}@{domain}",
                            extra={"username": username, "domain": domain},
                        )
                    except Exception:
                        self.logger.warning(
                            f"Failed to parse credentials from line: {line_stripped}",
                            exc_info=True,
                        )

            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=1.0,
                message="Password spraying completed",
            )

            return {
                "success": completed.returncode == 0,
                "found_credentials": len(credentials_found) > 0,
                "credentials": credentials_found,
                "returncode": completed.returncode,
                "stdout": output,
                "stderr": stderr_output,
            }

        except subprocess.TimeoutExpired:
            self.logger.error(
                f"Password spraying command timed out for {domain}",
                extra={"command": command, "domain": domain},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=1.0,
                message="Password spraying timed out",
            )
            return {
                "success": False,
                "found_credentials": False,
                "credentials": [],
                "returncode": -1,
                "stdout": "",
                "stderr": "Command timed out",
            }

        except Exception as e:
            telemetry.capture_exception(e)
            self.logger.exception(
                f"Error executing password spraying command for {domain}",
                extra={"command": command, "domain": domain},
                exc_info=True,
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=1.0,
                message="Password spraying failed with error",
            )
            return {
                "success": False,
                "found_credentials": False,
                "credentials": [],
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
            }
