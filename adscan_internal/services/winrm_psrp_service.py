"""Reusable WinRM/PSRP helpers for command execution and file transfer.

This service centralises the PSRP-backed operations that were previously
implemented ad hoc via ``nxc winrm -X``. The goal is to keep WinRM features
modular and reusable while preserving the legacy NetExec flows as fallbacks.
"""

from __future__ import annotations

import asyncio
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

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from adscan_core import telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    PostureSignal,
    SignalConfidence,
    TriState,
)
from adscan_internal.services._kerberos_spn import (
    normalize_kerberos_target_hostname as _normalize_kerberos_target_hostname,
)
from adscan_internal.services.posture_sink import PostureSink
from adscan_internal.services.auth_plan import (
    KERBEROS_FIRST_POLICY,
)
from adscan_internal.services.auth_error_classification import (
    is_pypsrp_kerberos_infra_error,
)

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.domain_posture import DomainPosture

# Module-level ccache cache: survives across WinRMPSRPService instances within
# the same process so the flag-collector loop doesn't re-issue a fresh AS-REQ
# for every denied path. Keyed by (username.lower(), domain.lower()).
# Entries expire after _CCACHE_TTL_SECONDS (conservative — well within the
# default 10-hour TGT lifetime).
_WINRM_CCACHE_CACHE: dict[tuple[str, str], tuple[str, float]] = {}
_CCACHE_TTL_SECONDS: float = 3600.0  # 1 h; TGT lifetime is typically 10 h


class WinRMPSRPError(RuntimeError):
    """Raised when a PSRP-backed WinRM operation fails."""


def is_clock_skew_error(exc: BaseException) -> bool:
    """Return True when *exc* indicates a Kerberos clock-skew / ticket-not-yet-valid failure.

    Covers both KRB_AP_ERR_SKEW (local clock behind DC) and KRB5KRB_AP_ERR_TKT_NYV
    (local clock ahead of DC / ticket start-time in the future).  The check is
    intentionally broad so it catches SpnegoError, WinRMPSRPError, and any other
    exception whose string representation contains one of the known markers.
    """
    lowered = str(exc).lower()
    return any(
        marker in lowered
        for marker in (
            "clock skew too great",
            "skew too great",
            "krb_ap_err_skew",
            "ticket not yet valid",
            "krb5krb_ap_err_tkt_nyv",
        )
    )


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
    has_http_ticket: bool
    has_wsman_ticket: bool
    matching_winrm_principals: list[str]
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
        kdc_ip: str | None = None,
        workspace_dir: str | None = None,
        posture_sink: Optional[PostureSink] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
        domain_for_posture: Optional[str] = None,
    ) -> None:
        self.domain = domain
        self.host = host
        self.username = username
        self.password = password
        self.kdc_ip: str | None = kdc_ip
        # Optional workspace root used to locate an already-minted Kerberos
        # ccache for this principal under
        # ``<workspace>/domains/<domain>/kerberos/tickets/<user>.ccache``.
        # When set, the plaintext-password Kerberos path prefers that ticket
        # over issuing a fresh AS-REQ. Back-compat: ``None`` keeps the legacy
        # behaviour (no workspace ccache lookup).
        self.workspace_dir: str | None = str(workspace_dir or "").strip() or None
        self.auth_mode = str(auth_mode or "auto").strip().lower() or "auto"
        # Promote short SPN host to FQDN. pypsrp builds the Kerberos SPN
        # ``http/<host>`` from this value; a short hostname yields a ticket the
        # target rejects with the same SEC_E_LOGON_DENIED pattern as LDAP/SMB.
        self.kerberos_spn_host = _normalize_kerberos_target_hostname(
            kerberos_spn_host, domain
        )
        self._client = None
        self._client_auth_settings: WinRMPSRPAuthSettings | None = None
        self._posture_sink: Optional[PostureSink] = posture_sink
        self._posture_snapshot: Optional["DomainPosture"] = posture_snapshot
        self._domain_for_posture: str = (
            str(domain_for_posture or "").strip() or str(domain or "").strip()
        )
        self._ntlm_fallback_allowed: bool = False
        # Track whether we have already emitted a NTLM_BIND_OK for this
        # service instance, so that batch operations on a long-lived
        # service do not flood the sink with duplicate signals.
        self._emitted_ntlm_success: bool = False
        # Cached ccache path obtained via NT hash → kerbad TGT. Reused across
        # multiple operations on the same instance; cleaned up on close/del.
        self._tgt_ccache_path: str | None = None

    # NOTE: instances do NOT own the lifecycle of the TGT ccache file.
    # The module-level cache (_WINRM_CCACHE_CACHE) is the owner — it survives
    # past instance destruction so the flag-collector's repeated cascade
    # invocations can reuse the same ccache without re-issuing an AS-REQ.
    # Stale entries get evicted by TTL (see _CCACHE_TTL_SECONDS) and the temp
    # files left behind in /tmp are cleaned by the OS on process exit.

    def _build_full_username(self) -> str:
        """Return the WinRM username in the format expected by PSRP."""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    def _build_kerberos_username(self) -> str:
        """Return a Kerberos principal name suitable for pyspnego/GSSAPI."""
        username = str(self.username or "").strip()
        if not username:
            return username
        if "@" in username:
            return username
        realm = str(self.domain or "").strip().upper()
        if realm:
            return f"{username}@{realm}"
        return username

    def _normalize_secret(self) -> str:
        """Normalize a password or bare NT hash for requests-ntlm."""
        secret = self.password
        if secret and re.fullmatch(r"[0-9A-Fa-f]{32}", secret):
            return f"{'0' * 32}:{secret}"
        return secret

    def _looks_like_ccache_path(self) -> bool:
        """Return True when the configured secret points to a Kerberos ccache."""
        return str(self.password or "").strip().lower().endswith(".ccache")

    def _looks_like_nt_hash(self) -> bool:
        """Return True when the configured secret is a bare 32-hex NT hash."""
        return bool(re.fullmatch(r"[0-9A-Fa-f]{32}", str(self.password or "").strip()))

    def _resolve_existing_workspace_ccache(self) -> str | None:
        """Return a valid workspace ccache path for this principal, if any.

        Looks up the canonical
        ``<workspace>/domains/<domain>/kerberos/tickets/<user>.ccache`` ticket
        (the same single-source-of-truth layout used by
        ``ensure_user_ccache``) and validates it via ``klist`` before handing
        it to pyspnego.  When the workspace directory is unknown or the ticket
        is missing/expired, returns ``None`` so the caller can fall back to a
        fresh kerbad AS-REQ.

        Returns ``None`` on any error (best-effort — never raises).
        """
        workspace_dir = self.workspace_dir
        if not workspace_dir:
            return None
        try:
            from adscan_internal.services.kerberos_ticket_service import (
                KerberosTicketService,
            )

            service = KerberosTicketService()
            ticket_path = service.get_ticket_for_user(
                workspace_dir=workspace_dir,
                domain=self.domain,
                username=self.username,
            )
            if not ticket_path:
                return None
            if not os.path.exists(ticket_path):
                return None
            # ``is_ticket_valid`` returns True/False/None (None = unable to
            # validate, e.g. klist absent).  Treat None as "assume usable" so a
            # container without klist still benefits from the workspace ticket;
            # only a definitive False (expired/unreadable) discards it.
            valid = service.is_ticket_valid(ticket_path=ticket_path)
            if valid is False:
                print_info_debug(
                    f"[winrm_psrp] workspace ccache present but invalid/expired for "
                    f"{mark_sensitive(self.username, 'user')}@"
                    f"{str(self.domain or '').upper()}; will mint a fresh TGT"
                )
                return None
            print_info_debug(
                f"[winrm_psrp] using existing workspace ccache for "
                f"{mark_sensitive(self.username, 'user')}@"
                f"{str(self.domain or '').upper()} "
                f"path={mark_sensitive(ticket_path, 'path')}"
            )
            return ticket_path
        except Exception as exc:  # noqa: BLE001 - best-effort lookup
            print_info_debug(
                f"[winrm_psrp] workspace ccache lookup failed (ignored): "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def _obtain_tgt_ccache_for_nt_hash(self) -> str | None:
        """Back-compat shim — prefetch a TGT+TGS ccache from the NT hash.

        Retained so existing call sites and tests that target the NT-hash entry
        point keep working.  Delegates to :meth:`_obtain_tgt_ccache`.
        """
        return self._obtain_tgt_ccache(nt_hash=self.password)

    def _obtain_tgt_ccache(
        self,
        *,
        password: str | None = None,
        nt_hash: str | None = None,
    ) -> str | None:
        """Request TGT + WinRM service ticket via kerbad and cache it on disk.

        Accepts either a plaintext ``password`` or a bare ``nt_hash`` (exactly
        one should be supplied).  Uses ``get_tgs`` (TGT → TGS in one call) so
        the resulting ccache contains both the TGT and the ``HTTP/<host>``
        service ticket.  pyspnego then finds the service ticket directly in the
        ccache without needing to contact the KDC — which may be unreachable or
        unconfigured in ``krb5.conf`` inside the container.

        kerbad resolves the KDC itself from ``kdc_ip`` (when provided) so this
        bypasses the broken system MIT krb5 that caused the GSSAPI
        ``Matching credential not found`` failure on plaintext-password
        Kerberos auth.

        The ccache path is stored in ``_tgt_ccache_path`` and reused for the
        lifetime of this service instance so repeated cascade retries don't
        issue a fresh AS-REQ each time.

        Returns ``None`` on failure (caller falls back to NTLM PTH).
        """
        if self._tgt_ccache_path:
            return self._tgt_ccache_path

        # Check the module-level cache so parallel / repeated cascade retries
        # don't each issue a fresh AS-REQ for the same credential.
        _cache_key = (
            str(self.username or "").lower(),
            str(self.domain or "").lower(),
        )
        _cached = _WINRM_CCACHE_CACHE.get(_cache_key)
        if _cached:
            _cached_path, _cached_at = _cached
            _fresh = time.time() - _cached_at < _CCACHE_TTL_SECONDS
            if _fresh and os.path.exists(_cached_path):
                self._tgt_ccache_path = _cached_path
                print_info_debug(
                    f"[winrm_psrp] reusing cached TGT+TGS ccache for "
                    f"{mark_sensitive(self.username, 'user')}@{str(self.domain or '').upper()}"
                )
                return self._tgt_ccache_path
            # Entry is stale or file vanished — evict it so we don't loop on a
            # dangling path.
            _WINRM_CCACHE_CACHE.pop(_cache_key, None)

        try:
            import concurrent.futures
            import tempfile

            from adscan_internal.services.kerberos_transport import (
                KerberosConfig,
                get_tgs,
            )

            kdc = self.kdc_ip or self.domain
            spn_host = (
                self.kerberos_spn_host
                or _normalize_kerberos_target_hostname(self.host, self.domain)
                or self.host
            )
            spn = f"HTTP/{spn_host}"
            krb_config = KerberosConfig(
                username=self.username,
                domain=self.domain,
                kdc_ip=kdc,
                password=password,
                nt_hash=nt_hash,
                posture_snapshot=self._posture_snapshot,
            )

            try:
                ccache_bytes = asyncio.run(get_tgs(krb_config, spn))
            except RuntimeError:
                # Already inside a running event loop (thread executor context).
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    ccache_bytes = pool.submit(
                        asyncio.run, get_tgs(krb_config, spn)
                    ).result(timeout=30)

            tmp = tempfile.NamedTemporaryFile(
                suffix=".ccache", prefix="adscan_winrm_tgt_", delete=False
            )
            tmp.write(ccache_bytes)
            tmp.close()
            self._tgt_ccache_path = tmp.name
            _WINRM_CCACHE_CACHE[_cache_key] = (tmp.name, time.time())
            _secret_kind = "NT hash" if nt_hash else "password"
            print_info_debug(
                f"[winrm_psrp] {_secret_kind} → TGT+TGS obtained for "
                f"{mark_sensitive(self.username, 'user')}@"
                f"{str(self.domain or '').upper()} spn={spn}"
            )
            return self._tgt_ccache_path
        except Exception as exc:
            print_info_debug(
                f"[winrm_psrp] TGT+TGS request failed, will fall back to NTLM: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def _resolve_auth_settings(self) -> WinRMPSRPAuthSettings:
        """Return the effective pypsrp authentication settings."""
        if self.auth_mode not in {"auto", "ntlm", "kerberos", "negotiate"}:
            raise WinRMPSRPError(
                f"Unsupported WinRM auth mode '{self.auth_mode}'. "
                "Expected one of: auto, ntlm, kerberos, negotiate."
            )

        # Posture-driven auth-mode override (PR11). When a posture snapshot
        # carries NTLM_AUTHENTICATION = DISABLED HIGH, force Kerberos so the
        # very first attempt skips the doomed NTLM bind. The plan is consulted
        # even when no posture snapshot is present so a caller-requested
        # Kerberos auth_mode inherits the NTLM-last-resort grant on a residual
        # KRB-ERROR (posture=None ⇒ NTLM not ruled out ⇒ grant allowed); the
        # chokepoint still gates the actual fallback on _is_kerberos_infra_error.
        try:
            from adscan_internal.services.auth_plan import (  # noqa: PLC0415
                build_winrm_plan,
            )

            plan = build_winrm_plan(
                requested_auth_mode=self.auth_mode,
                posture=self._posture_snapshot,
            )
            self._ntlm_fallback_allowed = plan.ntlm_fallback_allowed
            if plan.is_pruned:
                print_info_debug(
                    f"[winrm_psrp] posture plan: {plan.attempt.rationale}"
                )
                self.auth_mode = plan.attempt.auth_mode
        except Exception as plan_exc:  # pragma: no cover - defensive
            telemetry.capture_exception(plan_exc)
            print_info_debug(
                f"[winrm_psrp] posture plan resolution failed (ignored): "
                f"{type(plan_exc).__name__}: {plan_exc}"
            )

        if self.auth_mode == "auto":
            if KERBEROS_FIRST_POLICY:
                effective_auth = "kerberos"
                if self._posture_snapshot is None:
                    self._ntlm_fallback_allowed = True
            else:
                effective_auth = (
                    "kerberos" if self._looks_like_ccache_path() else "ntlm"
                )
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
            elif self._looks_like_nt_hash():
                # pyspnego/GSSAPI cannot use NT hash directly for Kerberos — it
                # needs either a ccache or a plaintext password to do AS-REQ.
                # Use kerbad to perform RC4 AS-REQ with the NT hash and obtain
                # a proper TGT ccache, then hand that to pyspnego.
                ccache_path = self._obtain_tgt_ccache_for_nt_hash()
                if ccache_path:
                    kerberos_ticket_path = ccache_path
                    password = None
                    username = None  # principal is embedded in the ccache
                else:
                    # TGT failed — NTLM fallback will handle it.
                    username = self._build_kerberos_username()
            elif not str(password or "").strip():
                password = None
            else:
                # Plaintext password + Kerberos. pyspnego cannot use the
                # container's system MIT krb5 to acquire its own TGT (no
                # krb5.conf / KDC resolution → GSSAPI "Matching credential not
                # found"). Mirror the NT-hash branch: prefer an existing
                # workspace ccache for this principal, else kerbad-prefetch a
                # TGT+TGS from the password (kerbad knows the KDC IP). On
                # success hand pyspnego the ticket; on failure fall through to
                # the password so the NTLM fallback can use it.
                ccache_path = self._resolve_existing_workspace_ccache()
                if not ccache_path:
                    ccache_path = self._obtain_tgt_ccache(password=password)
                if ccache_path:
                    kerberos_ticket_path = ccache_path
                    password = None
                    username = None  # principal is embedded in the ccache
                else:
                    username = self._build_kerberos_username()
            if not self._looks_like_ccache_path() and not str(username or "").strip():
                username = None

        return WinRMPSRPAuthSettings(
            auth=effective_auth,
            username=username,
            password=password,
            kerberos_ticket_path=kerberos_ticket_path,
            negotiate_hostname_override=(
                self.kerberos_spn_host
                or _normalize_kerberos_target_hostname(self.host, self.domain)
            )
            if effective_auth in {"kerberos", "negotiate"}
            else None,
            negotiate_service="HTTP"
            if effective_auth in {"kerberos", "negotiate"}
            else None,
        )

    @contextmanager
    def _temporary_kerberos_env(self, auth_settings: WinRMPSRPAuthSettings):
        """Temporarily bind the Kerberos ccache for GSSAPI-backed operations."""
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
        previous_gssapi_ccache: bytes | None = None
        gssapi_ccache_set = False
        os.environ["KRB5CCNAME"] = krb5ccname_value
        try:
            from gssapi.raw.ext_krb5 import krb5_ccache_name  # type: ignore[import]  # pylint: disable=no-name-in-module

            previous_gssapi_ccache = krb5_ccache_name(krb5ccname_value.encode("utf-8"))
            gssapi_ccache_set = True
        except Exception as exc:  # pragma: no cover - optional runtime dependency
            print_info_debug(
                "[winrm_psrp] unable to set thread-local GSSAPI ccache; "
                f"falling back to KRB5CCNAME only: {mark_sensitive(str(exc), 'text')}"
            )
        try:
            yield
        finally:
            if gssapi_ccache_set:
                try:
                    from gssapi.raw.ext_krb5 import krb5_ccache_name  # type: ignore[import]  # pylint: disable=no-name-in-module

                    krb5_ccache_name(previous_gssapi_ccache)
                except (
                    Exception
                ) as exc:  # pragma: no cover - optional runtime dependency
                    print_info_debug(
                        "[winrm_psrp] unable to restore thread-local GSSAPI ccache: "
                        + mark_sensitive(str(exc), "text")
                    )
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

    @staticmethod
    def _is_probable_kerberos_spn_key_mismatch(exc: BaseException) -> bool:
        """Return True when Kerberos failed because the selected service class is wrong."""
        lowered = str(exc or "").strip().lower()
        return "message stream modified" in lowered

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

    def _build_target_host_candidates(
        self,
        auth_settings: WinRMPSRPAuthSettings,
    ) -> set[str]:
        """Return lowercase host variants that may appear inside WinRM SPNs."""
        raw_candidates = {
            str(self.host or "").strip(),
            str(self.kerberos_spn_host or "").strip(),
            str(auth_settings.negotiate_hostname_override or "").strip(),
        }
        host_candidates: set[str] = set()
        for candidate in raw_candidates:
            candidate = candidate.lower()
            if not candidate:
                continue
            host_candidates.add(candidate)
            short_candidate = candidate.split(".", 1)[0].strip()
            if short_candidate:
                host_candidates.add(short_candidate)
        return host_candidates

    @staticmethod
    def _match_spn_service_for_hosts(
        principal: str,
        *,
        service_names: set[str],
        host_candidates: set[str],
    ) -> bool:
        """Return True when one principal matches a target service/host pair."""
        normalized = str(principal or "").strip().lower()
        if not normalized or "/" not in normalized:
            return False
        service_name, remainder = normalized.split("/", 1)
        if service_name not in service_names:
            return False
        host_part = remainder.split("@", 1)[0].strip()
        if not host_part:
            return False
        return host_part in host_candidates

    def _read_ccache_diagnostics_with_impacket(
        self,
        ticket_path: str,
    ) -> dict[str, Any]:
        """Return best-effort ccache diagnostics using kerbad's CCACHE parser."""
        try:
            from kerbad.common.ccache import CCACHE  # noqa: PLC0415
        except Exception as exc:  # pragma: no cover - optional runtime dependency
            return {"parser": "kerbad", "available": False, "error": str(exc)}

        try:
            ccache = CCACHE.from_file(ticket_path)
            primary_principal = None
            try:
                if ccache.primary_principal is not None:
                    primary_principal = ccache.primary_principal.to_spn()
            except Exception:
                primary_principal = None

            server_principals: list[str] = []
            has_tgt = False
            for cred in ccache.credentials or []:
                try:
                    server = cred.server.to_spn()
                except Exception:
                    server = ""
                server = server.strip()
                if not server:
                    continue
                server_principals.append(server)
                if "krbtgt" in server.lower():
                    has_tgt = True

            return {
                "parser": "kerbad",
                "available": True,
                "primary_principal": primary_principal,
                "server_principals": server_principals,
                "credential_count": len(server_principals),
                "has_tgt": has_tgt,
            }
        except Exception as exc:  # pragma: no cover - best effort diagnostics
            return {
                "parser": "kerbad",
                "available": True,
                "error": str(exc),
            }

    @staticmethod
    def _principal_to_text(value: object) -> str:
        """Return a Kerberos principal as plain text without Python bytes repr."""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace").strip()
        text = str(value or "").strip()
        if (text.startswith("b'") and text.endswith("'")) or (
            text.startswith('b"') and text.endswith('"')
        ):
            return text[2:-1].encode("utf-8").decode("unicode_escape").strip()
        return text

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

        ccache_diag = self._read_ccache_diagnostics_with_impacket(ticket_path)
        klist_diag = self._read_ccache_diagnostics_with_klist(ticket_path)

        ccache_servers = (
            ccache_diag.get("server_principals", [])
            if isinstance(ccache_diag, dict)
            else []
        )
        if isinstance(ccache_servers, list):
            ccache_servers = [
                str(item).strip() for item in ccache_servers if str(item).strip()
            ]
        else:
            ccache_servers = []

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
        if isinstance(ccache_diag, dict):
            lines.append(
                "impacket="
                f"available={ccache_diag.get('available')} "
                f"primary={ccache_diag.get('primary_principal') or '-'} "
                f"credentials={ccache_diag.get('credential_count') or 0} "
                f"has_tgt={ccache_diag.get('has_tgt')}"
            )
            if ccache_servers:
                lines.append(
                    "ccache_servers="
                    + ", ".join(ccache_servers[:8])
                    + (" ..." if len(ccache_servers) > 8 else "")
                )
            if ccache_diag.get("error"):
                lines.append(f"impacket_error={ccache_diag.get('error')}")
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

        ccache_diag = self._read_ccache_diagnostics_with_impacket(ticket_path)
        klist_diag = self._read_ccache_diagnostics_with_klist(ticket_path)

        primary_principal = None
        server_principals: list[str] = []
        has_tgt = False
        host_candidates = self._build_target_host_candidates(auth_settings)

        if isinstance(ccache_diag, dict):
            primary_principal = (
                self._principal_to_text(ccache_diag.get("primary_principal") or "")
                or None
            )
            raw_servers = ccache_diag.get("server_principals", [])
            if isinstance(raw_servers, list):
                server_principals = [
                    self._principal_to_text(item)
                    for item in raw_servers
                    if self._principal_to_text(item)
                ]
            has_tgt = bool(ccache_diag.get("has_tgt"))

        if not primary_principal and isinstance(klist_diag, dict):
            primary_principal = (
                str(klist_diag.get("default_principal") or "").strip() or None
            )
        if not server_principals and isinstance(klist_diag, dict):
            raw_servers = klist_diag.get("server_principals", [])
            if isinstance(raw_servers, list):
                server_principals = [
                    self._principal_to_text(item)
                    for item in raw_servers
                    if self._principal_to_text(item)
                ]
        if not has_tgt:
            has_tgt = any(
                item.lower().startswith("krbtgt/") for item in server_principals
            )

        matching_http_principals = [
            item
            for item in server_principals
            if self._match_spn_service_for_hosts(
                item,
                service_names={"http"},
                host_candidates=host_candidates,
            )
        ]
        matching_wsman_principals = [
            item
            for item in server_principals
            if self._match_spn_service_for_hosts(
                item,
                service_names={"wsman"},
                host_candidates=host_candidates,
            )
        ]
        matching_winrm_principals = matching_http_principals + [
            item
            for item in matching_wsman_principals
            if item not in matching_http_principals
        ]
        service_ticket_only = bool(server_principals) and not has_tgt
        return WinRMPSRPCcacheDiagnosticsSummary(
            ticket_path=ticket_path,
            primary_principal=primary_principal,
            server_principals=server_principals,
            has_tgt=has_tgt,
            has_http_ticket=bool(matching_http_principals),
            has_wsman_ticket=bool(matching_wsman_principals),
            matching_winrm_principals=matching_winrm_principals,
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
            f"has_tgt={summary.has_tgt}, "
            f"has_http_ticket={summary.has_http_ticket}, "
            f"has_wsman_ticket={summary.has_wsman_ticket}, "
            f"matching_winrm_principals={mark_sensitive(', '.join(summary.matching_winrm_principals[:4]) or '-', 'text')}. "
            "This ccache contains delegated service tickets but no krbtgt/TGT; "
            "pypsrp/pyspnego on Linux often cannot start WinRM sessions from "
            "service-ticket-only caches."
        )
        raise WinRMPSRPError(
            "WinRM PSRP cannot use this Kerberos ccache because it only contains "
            "service tickets and no krbtgt/TGT. "
            + (
                "A matching WinRM HTTP/WSMAN ticket for the target host is present, "
                "but pypsrp/pyspnego on Linux still usually requires a TGT-backed cache. "
                if summary.matching_winrm_principals
                else "No matching WinRM HTTP/WSMAN ticket for the target host was found in the cache. "
            )
            + "This commonly happens with RBCD HTTP service tickets generated by "
            "getST.py; SMB/Impacket may still work, but pypsrp/pyspnego usually "
            "requires a TGT-backed cache."
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

    def _build_ntlm_auth_settings(self) -> WinRMPSRPAuthSettings:
        """Return NTLM settings for Kerberos-first infra fallback."""
        return WinRMPSRPAuthSettings(
            auth="ntlm",
            username=self._build_full_username(),
            password=self._normalize_secret(),
        )

    @staticmethod
    def _is_kerberos_infra_error(exc: BaseException) -> bool:
        """Return True when a Kerberos WinRM failure is infrastructure-related."""
        return is_pypsrp_kerberos_infra_error(exc)

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
            # "Matching credential not found" is overloaded: with a ccache it
            # usually means the HTTP/<host> service ticket isn't present and a
            # WSMAN service-class retry resolves it; WITHOUT a ccache it means
            # pyspnego could not acquire its own TGT (the broken container
            # krb5) and only NTLM can save the operation. Prefer the WSMAN
            # service-class retry first when it is still available so the
            # in-ccache SPN case is not short-circuited to NTLM.
            wsman_fallback_auth = self._retry_auth_settings_with_wsmam_fallback(
                auth_settings
            )
            # The WSMAN service-class retry only helps when an actual ccache is
            # in play (the HTTP/<host> ticket may be missing while a
            # WSMAN/<host> ticket exists). Without a ccache the failure is the
            # local-credential acquisition failure, which only NTLM can fix.
            has_ccache = bool(str(auth_settings.kerberos_ticket_path or "").strip())
            wsman_retry_available = bool(
                wsman_fallback_auth
                and has_ccache
                and (
                    self._is_matching_credential_not_found_error(exc)
                    or self._is_probable_kerberos_spn_key_mismatch(exc)
                )
            )
            if (
                auth_settings.auth == "kerberos"
                and self._ntlm_fallback_allowed
                and self._is_kerberos_infra_error(exc)
                and not wsman_retry_available
            ):
                # Note: auth_mode == "auto" guard removed — the posture plan
                # legitimately changes auth_mode from "auto" to "kerberos"
                # before this path is reached, which previously blocked the
                # fallback even when _ntlm_fallback_allowed=True.
                print_info_debug(
                    "[winrm_psrp] Kerberos infra error — retrying with NTLM"
                )
                self._client = None
                self._client_auth_settings = None
                fallback_auth = self._build_ntlm_auth_settings()
                fallback_client = self._get_client(fallback_auth)
                with self._temporary_kerberos_env(fallback_auth):
                    return operation(fallback_client, fallback_auth)

            fallback_auth = wsman_fallback_auth
            if not (
                fallback_auth
                and (
                    self._is_matching_credential_not_found_error(exc)
                    or self._is_probable_kerberos_spn_key_mismatch(exc)
                )
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
            command_preview = build_text_preview(script or "", head=20, tail=20, max_line_length=300)
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

    # ------------------------------------------------------------------ #
    # Posture signal emission (PR11)
    # ------------------------------------------------------------------ #

    def _emit_posture_signal(
        self,
        *,
        category: ConstraintCategory,
        state: TriState,
        confidence: SignalConfidence,
        signal_code: str,
        message: str,
    ) -> None:
        """Best-effort emit of a posture signal to the configured sink.

        Sink failures are captured via telemetry and silently swallowed —
        posture telemetry must never break a WinRM operation.
        """
        if self._posture_sink is None or not self._domain_for_posture:
            return
        try:
            signal = PostureSignal(
                domain=self._domain_for_posture,
                category=category,
                state=state,
                confidence=confidence,
                source="winrm_transport",
                signal_code=signal_code,
                message=message,
                protocol="winrm",
                observed_at=datetime.now(timezone.utc),
            )
            self._posture_sink(signal)
        except Exception as sink_exc:  # noqa: BLE001
            telemetry.capture_exception(sink_exc)
            print_info_debug(
                f"[winrm_psrp] posture sink failed: "
                f"{type(sink_exc).__name__}: {sink_exc}"
            )

    @staticmethod
    def _is_ntlm_like_auth(auth_mode: str) -> bool:
        """True when the resolved auth_mode used the NTLM credential path."""
        return str(auth_mode or "").strip().lower() in {"ntlm", "negotiate"}

    _NTLM_BLOCKED_MARKERS_WINRM = (
        "STATUS_LOGON_FAILURE",
        "NTLM",
        "NTLMSSP",
    )

    def _emit_winrm_failure_posture(self, *, exc: BaseException) -> None:
        """Classify one PSRP failure and emit any matching posture signals.

        Single rule: when the underlying attempt used NTLM (auth_mode ==
        ``ntlm`` or ``negotiate``) and the exception text contains one of
        ``_NTLM_BLOCKED_MARKERS_WINRM``, emit
        ``NTLM_AUTHENTICATION = DISABLED (HIGH)``.

        Other failure shapes (clock skew, transport, access denied) are not
        domain-level NTLM hardening evidence and are intentionally ignored.
        """
        effective_auth = (
            self._client_auth_settings.auth
            if self._client_auth_settings is not None
            else self.auth_mode
        )
        if not self._is_ntlm_like_auth(effective_auth):
            return
        msg_upper = str(exc or "").upper()
        if not any(m in msg_upper for m in self._NTLM_BLOCKED_MARKERS_WINRM):
            return
        self._emit_posture_signal(
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="NTLM_REJECTED_VIA_WINRM",
            message=(
                "DC rejected NTLM auth over WinRM — NTLM appears disabled by policy"
            ),
        )

    def _emit_winrm_success_posture(self) -> None:
        """Emit posture signals after a successful PSRP operation.

        - NTLM (or Negotiate that resolved to NTLM) success →
          ``NTLM_AUTHENTICATION = ENABLED (MEDIUM)``.
        - Kerberos success is intentionally not emitted — it is the default
          and carries no hardening signal.
        """
        if self._emitted_ntlm_success:
            return
        effective_auth = (
            self._client_auth_settings.auth
            if self._client_auth_settings is not None
            else self.auth_mode
        )
        if not self._is_ntlm_like_auth(effective_auth):
            return
        self._emitted_ntlm_success = True
        self._emit_posture_signal(
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            state=TriState.ENABLED,
            confidence=SignalConfidence.MEDIUM,
            signal_code="NTLM_BIND_OK_WINRM",
            message="NTLM authentication via WinRM succeeded",
        )

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
            self._emit_winrm_failure_posture(exc=exc)
            raise WinRMPSRPError(
                f"WinRM PSRP PowerShell execution failed on {self.host}: {exc}"
            ) from exc
        duration_seconds = time.perf_counter() - started_at
        # PSRP session established successfully — emit the success signal
        # regardless of inner script errors (those are remote-side, not auth).
        self._emit_winrm_success_posture()

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

    async def async_execute_powershell(
        self,
        script: str,
        *,
        operation_name: str | None = None,
        require_logon_bypass: bool = False,
    ) -> WinRMPSRPExecutionResult:
        """Execute PowerShell without blocking the caller's event loop.

        ``pypsrp`` uses a synchronous ``requests`` transport. Keep the proven
        PSRP implementation as-is and move the blocking session work into the
        default executor for async collection flows.
        """
        return await asyncio.to_thread(
            self.execute_powershell,
            script,
            operation_name=operation_name,
            require_logon_bypass=require_logon_bypass,
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

    async def async_fetch_files(
        self,
        paths: Iterable[str],
        download_dir: str,
    ) -> list[str]:
        """Download remote files without blocking the caller's event loop."""
        path_list = list(paths)
        return await asyncio.to_thread(self.fetch_files, path_list, download_dir)

    def fetch_file(self, remote_path: str, save_path: str) -> str:
        """Download one remote file to one explicit local path via PSRP."""
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        try:
            self._execute_with_kerberos_service_fallback(
                lambda client, _auth_settings: client.fetch(remote_path, save_path),
                operation_name="winrm_fetch_file",
            )
        except Exception as exc:  # pragma: no cover - network/runtime specific
            print_info_debug(
                "[winrm_psrp] native fetch failed; falling back to chunked "
                f"PowerShell download for {mark_sensitive(remote_path, 'path')}: "
                f"{mark_sensitive(str(exc), 'text')}"
            )
            try:
                self._fetch_file_via_powershell_chunks(remote_path, save_path)
            except Exception as fallback_exc:  # noqa: BLE001
                raise WinRMPSRPError(
                    f"WinRM PSRP file download failed for {remote_path} on "
                    f"{self.host}: {exc}; fallback failed: {fallback_exc}"
                ) from fallback_exc
        return save_path

    def _fetch_file_via_powershell_chunks(
        self,
        remote_path: str,
        save_path: str,
        *,
        chunk_size: int = 192 * 1024,
    ) -> None:
        """Download one remote file as Base64 chunks over PSRP command output.

        ``pypsrp.Client.fetch`` can fail on some user-profile temp paths even
        when the same PSRP session can read the file. This fallback is slower
        but transport-compatible and keeps batched acquisition reliable.
        """
        quoted_path = self._escape_ps_single_quoted(remote_path)
        stat_script = (
            "$ErrorActionPreference='Stop';"
            f"$path='{quoted_path}';"
            "if(-not (Test-Path -LiteralPath $path -PathType Leaf)){"
            ' throw "remote file not found: $path"'
            "};"
            "$item=Get-Item -LiteralPath $path -ErrorAction Stop;"
            "[PSCustomObject]@{Length=$item.Length} | ConvertTo-Json -Compress"
        )
        stat = self.execute_powershell(
            stat_script,
            operation_name="winrm_fetch_file_stat",
        )
        if stat.had_errors and not stat.stdout.strip():
            raise WinRMPSRPError(stat.stderr or "remote file stat failed")
        try:
            file_size = int(json.loads(stat.stdout.strip()).get("Length") or 0)
        except (json.JSONDecodeError, AttributeError, ValueError) as exc:
            raise WinRMPSRPError("remote file stat returned invalid JSON") from exc

        with open(save_path, "wb") as handle:
            offset = 0
            while offset < file_size:
                count = min(chunk_size, file_size - offset)
                chunk_script = (
                    "$ErrorActionPreference='Stop';"
                    f"$path='{quoted_path}';"
                    f"$offset={offset};"
                    f"$count={count};"
                    "$buffer=New-Object byte[] $count;"
                    "$stream=[System.IO.File]::Open("
                    "$path,"
                    "[System.IO.FileMode]::Open,"
                    "[System.IO.FileAccess]::Read,"
                    "[System.IO.FileShare]::ReadWrite"
                    ");"
                    "try {"
                    " [void]$stream.Seek($offset,[System.IO.SeekOrigin]::Begin);"
                    " $read=$stream.Read($buffer,0,$count);"
                    " [Convert]::ToBase64String($buffer,0,$read)"
                    "} finally {"
                    " $stream.Close()"
                    "}"
                )
                chunk = self.execute_powershell(
                    chunk_script,
                    operation_name="winrm_fetch_file_chunk",
                )
                if chunk.had_errors and not chunk.stdout.strip():
                    raise WinRMPSRPError(
                        chunk.stderr or f"remote file chunk read failed at {offset}"
                    )
                try:
                    data = base64.b64decode(chunk.stdout.strip(), validate=True)
                except Exception as exc:  # noqa: BLE001
                    raise WinRMPSRPError(
                        f"remote file chunk returned invalid base64 at {offset}"
                    ) from exc
                if not data and count > 0:
                    raise WinRMPSRPError(f"remote file chunk was empty at {offset}")
                handle.write(data)
                offset += len(data)

    async def async_fetch_file(self, remote_path: str, save_path: str) -> str:
        """Download one remote file without blocking the caller's event loop."""
        return await asyncio.to_thread(self.fetch_file, remote_path, save_path)

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

    async def async_upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload one local file without blocking the caller's event loop."""
        return await asyncio.to_thread(self.upload_file, local_path, remote_path)

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
                    "RelativePath": relative_path.replace("\\", "/"),
                }
                for remote_path, relative_path in files
            ]
        )
        escaped_manifest = self._escape_ps_single_quoted(manifest_json)
        script_lines = [
            "$ErrorActionPreference='Stop'",
            "$guid=[guid]::NewGuid().Guid",
            "$tempRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Temp'",
            "if(-not $tempRoot -or -not (Test-Path -LiteralPath $tempRoot)){ $tempRoot=$env:TEMP }",
            "$stageRoot=Join-Path $tempRoot ('adscan_psrp_stage_'+$guid)",
            "$archivePath=Join-Path $tempRoot ('adscan_psrp_stage_'+$guid+'.zip')",
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
            "    try {",
            "        Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $archivePath -Force",
            "    } catch {",
            "        $skipped += [PSCustomObject]@{",
            "            RemotePath = $archivePath",
            "            Reason = 'Compress-Archive failed: ' + $_.Exception.Message",
            "        }",
            "    }",
            "    if(-not (Test-Path -LiteralPath $archivePath -PathType Leaf)){",
            "        Add-Type -AssemblyName System.IO.Compression.FileSystem",
            "        if(Test-Path -LiteralPath $archivePath){ Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue }",
            "        [System.IO.Compression.ZipFile]::CreateFromDirectory($stageRoot, $archivePath)",
            "    }",
            "    if(-not (Test-Path -LiteralPath $archivePath -PathType Leaf)){",
            '        throw "archive was not created: $archivePath"',
            "    }",
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
            _zip_size = os.path.getsize(temp_archive_path) if os.path.exists(temp_archive_path) else 0
            print_info_debug(
                f"[batch_fetch] archive downloaded: size={_zip_size} bytes "
                f"path={mark_sensitive(temp_archive_path, 'path')}"
            )
            with zipfile.ZipFile(temp_archive_path, "r") as archive_handle:
                _zip_entries = [i.filename for i in archive_handle.infolist()]
                print_info_debug(
                    f"[batch_fetch] ZIP entries ({len(_zip_entries)}): {_zip_entries[:10]}"
                )
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

        for _remote_path, relative_path in file_list:
            save_path = Path(download_dir) / relative_path
            if save_path.exists():
                continue
            legacy_path = Path(download_dir) / relative_path.replace("/", "\\")
            if not legacy_path.exists() or legacy_path == save_path:
                continue
            save_path.parent.mkdir(parents=True, exist_ok=True)
            legacy_path.replace(save_path)

        downloaded_files: list[str] = []
        for _remote_path, relative_path in file_list:
            save_path = str(Path(download_dir) / relative_path)
            if os.path.exists(save_path):
                downloaded_files.append(save_path)
        print_info_debug(
            f"[batch_fetch] downloaded ({len(downloaded_files)}/{len(file_list)}): "
            f"{[os.path.basename(f) for f in downloaded_files]}"
        )
        return WinRMPSRPBatchFetchResult(
            downloaded_files=downloaded_files,
            staged_file_count=staged_file_count,
            skipped_files=skipped_files,
        )

    async def async_fetch_files_batched(
        self,
        *,
        files: Iterable[tuple[str, str]],
        download_dir: str,
    ) -> WinRMPSRPBatchFetchResult:
        """Stage and fetch files without blocking the caller's event loop."""
        file_list = list(files)
        return await asyncio.to_thread(
            self.fetch_files_batched,
            files=file_list,
            download_dir=download_dir,
        )
