"""Kerberos ticket generation service.

This module encapsulates the logic required to:

* Generate Kerberos TGTs and ``ccache`` files from domain credentials
  (password, NTLM hash, or typed Kerberos AES key material).
* Prepare a minimal Kerberos environment (``KRB5_CONFIG`` and
  ``KRB5CCNAME``) suitable for external tools that rely on the system
  Kerberos stack.

The goal is to extract ticket-related logic out of ``adscan.py`` so it
can be reused by both the CLI and future frontends (e.g. a web backend),
following the service-layer architecture used in the rest of the project.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Optional
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time

from adscan_internal.command_runner import (
    CommandRunner,
    CommandSpec,
    build_execution_output_preview,
    summarize_execution_result,
)
from adscan_internal.services.base_service import BaseService
from adscan_internal.core import EventBus, LicenseMode
from adscan_internal.subprocess_env import get_clean_env_for_compilation
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error_debug,
    print_info_debug,
    print_warning_debug,
)
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_panel,
    print_success,
)
from adscan_internal.services.credential_store_service import (
    CredentialStoreService,
    KerberosKeyMaterial,
)

if TYPE_CHECKING:  # pragma: no cover - import-time decoupling only
    from adscan_internal.services.domain_posture import DomainPosture


@dataclass
class KerberosTGTResult:
    """Result of a Kerberos TGT generation operation.

    Attributes:
        username: Account used to request the ticket.
        domain: Target Kerberos realm / AD domain.
        ticket_path: Path to the resulting ccache file (if any).
        method: Backend used to obtain the ticket (``impacket_password``,
            ``impacket_ntlm`` or ``kinit``).
        success: Whether the operation completed successfully.
        error_message: Optional human-readable error description.
    """

    username: str
    domain: str
    ticket_path: Optional[str]
    method: str
    success: bool
    error_message: Optional[str] = None
    error_kind: Optional[str] = None  # e.g. "rc4_disabled"


@dataclass
class KerberosServiceTicketResult:
    """Result of a Kerberos service ticket (S4U) generation operation.

    Attributes:
        target_user: Account being impersonated in the S4U operation.
        spn: Service Principal Name used for the ticket.
        success: Whether the operation completed successfully.
        error_message: Optional human-readable error description.
        command: Optional string representation of the executed command.
    """

    target_user: str
    spn: str
    success: bool
    error_message: Optional[str] = None
    command: Optional[str] = None
    ticket_path: Optional[str] = None


@dataclass
class KerberosEnvironmentStatus:
    """Status of the current Kerberos environment for a command.

    Attributes:
        krb5_config_ready: Whether KRB5_CONFIG points to an existing file.
        kerberos_ticket_ready: Whether KRB5CCNAME points to an existing ticket.
        ready_for_kerberos_commands: True when the environment is usable for
            Kerberos operations (config + ticket when username is provided).
        krb5_config_path: Resolved path of the Kerberos configuration file.
        ticket_path: Resolved path of the Kerberos ticket (ccache).
        issues: List of human-readable issues detected during validation.
    """

    krb5_config_ready: bool = False
    kerberos_ticket_ready: bool = False
    ready_for_kerberos_commands: bool = False
    krb5_config_path: Optional[str] = None
    ticket_path: Optional[str] = None
    issues: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.issues is None:
            self.issues = []


# ---------------------------------------------------------------------------
# S4U UX helpers — premium Rich CLI output for forwardable ticket generation
# ---------------------------------------------------------------------------

_ETYPE_LABELS_S4U: dict[str, str] = {
    "23": "RC4-HMAC",
    "17": "AES-128",
    "18": "AES-256",
}

_S4U_ERROR_MAP = (
    (
        "error code (16)",
        "Delegation not configured on this account — ensure RBCD is set",
    ),
    ("kdc_err_badoption", "KDC rejected S4U — verify RBCD delegation write succeeded"),
    (
        "kdc_err_preauth_failed",
        "Authentication failed — wrong password or AES salt mismatch",
    ),
    ("clock skew", "Clock skew too large — sync clocks before retrying"),
    ("krb_ap_err_skew", "Clock skew too large — sync clocks before retrying"),
    ("connection refused", "KDC unreachable — verify DC IP and network connectivity"),
    ("s4u2self failed", "S4U2Self rejected — account may lack delegation rights"),
    (
        "s4u2proxy failed",
        "S4U2Proxy rejected — RBCD target mismatch or delegation not enabled",
    ),
)


def _etype_label(etype_key: str | None) -> str:
    return _ETYPE_LABELS_S4U.get(
        etype_key or "", f"etype {etype_key}" if etype_key else "?"
    )


def _styled_etype_s4u(etype_key: str | None) -> str:
    label = _etype_label(etype_key)
    if label.startswith("RC4"):
        return f"[bold green]{label}[/bold green]"
    if label.startswith("AES"):
        return f"[bold yellow]{label}[/bold yellow]"
    return label


def _classify_s4u_error(msg: str) -> str:
    lower = (msg or "").lower()
    for marker, friendly in _S4U_ERROR_MAP:
        if marker in lower:
            return friendly
    return msg or "Unknown S4U error"


def _render_s4u_preflight(
    *,
    domain: str,
    kdc_ip: str,
    s4u_account: str,
    target_user: str,
    spn: str,
    ccache_path: str,
) -> None:
    from rich.table import Table  # noqa: PLC0415

    tbl = Table.grid(padding=(0, 2))
    tbl.add_column(style="dim")
    tbl.add_column()
    tbl.add_row("Domain", mark_sensitive(domain, "domain"))
    tbl.add_row("KDC", mark_sensitive(kdc_ip, "ip"))
    tbl.add_row("Delegating account", mark_sensitive(s4u_account, "user"))
    tbl.add_row("Impersonate", mark_sensitive(target_user, "user"))
    tbl.add_row("Service SPN", spn)
    tbl.add_row("ccache output", ccache_path)
    print_panel(tbl, title="S4U Forwardable Ticket", border_style="blue")


def _render_s4u_step(step: int, name: str, msg: str) -> None:
    print_info(f"  [{step}/3] [dim]{name}[/dim]  → {msg}")


def _render_s4u_step_ok(step: int, name: str, detail: str) -> None:
    print_success(f"  [{step}/3] [bold]{name}[/bold]  ✓  {detail}")


def _render_s4u_step_fail(step: int, name: str, detail: str) -> None:
    print_error(f"  [{step}/3] [bold]{name}[/bold]  ✗  {detail}")


def _render_s4u_ticket_panel(
    *,
    target_user: str,
    spn: str,
    etype_key: str | None,
    ccache_path: str,
    ccache_size: int,
) -> None:
    from rich.table import Table  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415
    from rich.console import Group  # noqa: PLC0415

    tbl = Table.grid(padding=(0, 2))
    tbl.add_column(style="dim")
    tbl.add_column()
    tbl.add_row("Impersonated user", mark_sensitive(target_user, "user"))
    tbl.add_row("Service SPN", spn)
    tbl.add_row("Encryption", _styled_etype_s4u(etype_key))
    tbl.add_row("ccache path", ccache_path)
    tbl.add_row("ccache size", f"{ccache_size} B")
    export_hint = Text(f"\nexport KRB5CCNAME={ccache_path}", style="bold cyan")
    print_panel(
        Group(tbl, export_hint),
        title="[bold green]✓  Forwardable Ticket Ready[/bold green]",
        border_style="green",
    )


class _RichOutputLoggerAdapter:
    """Minimal logger-like adapter backed by Rich output debug helpers.

    Kerberos service internals historically used ``self.logger`` (stdlib logging).
    For CLI-centric observability we route those messages through the centralized
    ``print_*_debug`` helpers so they are consistently visible/logged.
    """

    def __init__(self, component: str) -> None:
        self._component = component

    @staticmethod
    def _infer_data_type(raw_value: str) -> str:
        """Best-effort sensitive type inference for telemetry markers."""
        value = (raw_value or "").strip()
        if not value:
            return "user"

        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass

        if value.startswith(("/", "./", "../", "~")) or "\\" in value:
            return "path"

        if ":" in value and "/" in value and " " not in value:
            return "password"

        if "." in value and " " not in value:
            return "domain"

        return "user"

    @classmethod
    def _sanitize(cls, value: Any) -> str:
        """Return a debug-safe, marker-wrapped representation for output."""
        if isinstance(value, Path):
            return mark_sensitive(str(value), "path")
        if isinstance(value, Mapping):
            return ", ".join(f"{k}={cls._sanitize(v)}" for k, v in value.items())
        if isinstance(value, (list, tuple, set)):
            return "[" + ", ".join(cls._sanitize(v) for v in value) + "]"

        text = str(value)
        return mark_sensitive(text, cls._infer_data_type(text))

    def _format(self, message: Any, *args: Any, **kwargs: Any) -> str:
        """Format logging-style messages with `%s` placeholders."""
        base = str(message)
        if args:
            sanitized_args = tuple(self._sanitize(arg) for arg in args)
            try:
                base = base % sanitized_args
            except Exception:
                base = f"{base} " + " ".join(sanitized_args)

        extra = kwargs.get("extra")
        if extra:
            base = f"{base} | extra={self._sanitize(extra)}"

        return f"[{self._component}] {base}"

    def debug(self, message: Any, *args: Any, **kwargs: Any) -> None:
        print_info_debug(self._format(message, *args, **kwargs))

    def info(self, message: Any, *args: Any, **kwargs: Any) -> None:
        print_info_debug(self._format(message, *args, **kwargs))

    def warning(self, message: Any, *args: Any, **kwargs: Any) -> None:
        print_warning_debug(self._format(message, *args, **kwargs))

    def error(self, message: Any, *args: Any, **kwargs: Any) -> None:
        print_error_debug(self._format(message, *args, **kwargs))

    def exception(self, message: Any, *args: Any, **kwargs: Any) -> None:
        exc_obj: BaseException | None = None
        exc_info = kwargs.get("exc_info")
        if isinstance(exc_info, BaseException):
            exc_obj = exc_info
        elif isinstance(exc_info, tuple) and len(exc_info) >= 2:
            candidate = exc_info[1]
            if isinstance(candidate, BaseException):
                exc_obj = candidate
        elif exc_info:
            candidate = sys.exc_info()[1]
            if isinstance(candidate, BaseException):
                exc_obj = candidate

        text = self._format(message, *args, **kwargs)
        if exc_obj is not None:
            text = f"{text} | exception={self._sanitize(exc_obj)}"
        print_error_debug(text)


def _write_ccache_bytes(ccache_bytes: bytes, ccache_path: Path) -> str:
    """Write raw ccache bytes to a file and return the path string."""
    ccache_path.parent.mkdir(parents=True, exist_ok=True)
    ccache_path.write_bytes(ccache_bytes)
    return str(ccache_path)


async def _s4u_forwardable_ticket_async(
    *,
    domain: str,
    pdc_ip: str,
    s4u_account: str,
    s4u_password: str,
    target_user: str,
    spn: str,
    ccache_path: Path,
) -> "KerberosServiceTicketResult":
    """Async core for :meth:`KerberosTicketService.create_forwardable_ticket_native`.

    Extracted as a module-level coroutine so both the sync method (via
    ``asyncio.run()``) and async callers (lab runner, exploitation chains) can
    invoke it directly without nesting event loops.
    """
    import tempfile as _tempfile
    import urllib.parse as _up

    from adscan_internal.services.kerberos_transport import (  # noqa: PLC0415
        KerberosConfig,
        get_tgt,
    )
    from kerbad.aioclient import AIOKerberosClient  # noqa: PLC0415
    from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415
    from kerbad.common.spn import KerberosSPN  # noqa: PLC0415

    # ── Step 1: TGT ───────────────────────────────────────────────────────────
    _render_s4u_step(1, "TGT", f"Authenticating as {s4u_account}...")
    try:
        krb_config = KerberosConfig(
            domain=domain,
            kdc_ip=pdc_ip,
            username=s4u_account.rstrip("$"),
            password=s4u_password,
        )
        tgt_bytes = await get_tgt(krb_config)
    except Exception as exc:
        msg = _classify_s4u_error(str(exc))
        _render_s4u_step_fail(1, "TGT", msg)
        return KerberosServiceTicketResult(
            target_user=target_user, spn=spn, success=False, error_message=msg
        )

    with _tempfile.NamedTemporaryFile(
        suffix=".ccache", prefix="adscan_tgt_", delete=False
    ) as _tmp:
        _tgt_path = _tmp.name
        _tmp.write(tgt_bytes)

    ccache_url = (
        f"kerberos+ccache://{_up.quote(domain, safe='')}\\{_up.quote(s4u_account.rstrip('$'), safe='')}:"
        f"{_up.quote(_tgt_path, safe='')}@{pdc_ip}"
    )
    factory = KerberosClientFactory.from_url(ccache_url)
    client: AIOKerberosClient = factory.get_client()
    client.tgt_from_ccache()
    _render_s4u_step_ok(1, "TGT", f"ccache {len(tgt_bytes)}B")

    # ── Step 2: S4U2Self ──────────────────────────────────────────────────────
    _render_s4u_step(2, "S4U2Self", f"Impersonating {target_user}...")
    try:
        user_spn = KerberosSPN.from_upn(f"{target_user}@{domain}")
        tgs_self, _enc_self, _key_self = await client.with_clock_skew(
            client.S4U2self, user_spn
        )
    except Exception as exc:
        msg = _classify_s4u_error(str(exc))
        _render_s4u_step_fail(2, "S4U2Self", msg)
        return KerberosServiceTicketResult(
            target_user=target_user, spn=spn, success=False, error_message=msg
        )
    _render_s4u_step_ok(2, "S4U2Self", f"forwardable ticket for {target_user}")

    # ── Step 3: S4U2Proxy ─────────────────────────────────────────────────────
    _render_s4u_step(3, "S4U2Proxy", f"Requesting {spn}...")
    try:
        svc_spn = KerberosSPN.from_spn(spn, default_realm=domain)
        _tgs_proxy, _enc_proxy, key_proxy = await client.with_clock_skew(
            client.S4U2proxy, tgs_self["ticket"], svc_spn
        )
    except Exception as exc:
        msg = _classify_s4u_error(str(exc))
        _render_s4u_step_fail(3, "S4U2Proxy", msg)
        return KerberosServiceTicketResult(
            target_user=target_user, spn=spn, success=False, error_message=msg
        )

    etype_key: str | None = None
    try:
        etype_val = getattr(key_proxy, "enctype", None) or getattr(
            key_proxy, "etype", None
        )
        if etype_val is not None:
            etype_key = str(int(etype_val))
    except Exception:
        pass

    ccache_bytes = client.ccache.to_bytes()
    ccache_path.write_bytes(ccache_bytes)

    _render_s4u_step_ok(
        3, "S4U2Proxy", f"[{_etype_label(etype_key)}]  {ccache_path.name}"
    )
    _render_s4u_ticket_panel(
        target_user=target_user,
        spn=spn,
        etype_key=etype_key,
        ccache_path=str(ccache_path),
        ccache_size=len(ccache_bytes),
    )

    return KerberosServiceTicketResult(
        target_user=target_user,
        spn=spn,
        success=True,
        ticket_path=str(ccache_path),
    )


class KerberosTicketService(BaseService):
    """Service responsible for generating Kerberos tickets (TGT).

    This class emits diagnostic output via centralized Rich debug helpers and returns
    :class:`KerberosTGTResult` / :class:`KerberosEnvironmentStatus`
    instances. The CLI (or any other frontend) is responsible for
    turning those results into user-facing messages.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        license_mode: LicenseMode = LicenseMode.PRO,
    ):
        """Initialize KerberosTicketService.

        Args:
            event_bus: Event bus for progress tracking (optional).
            license_mode: License mode (LITE or PRO). Currently no license
                restrictions are enforced for TGT generation.
        """
        super().__init__(event_bus=event_bus, license_mode=license_mode)
        self.logger = _RichOutputLoggerAdapter(component="kerberos")
        self._command_runner = CommandRunner()

    # --------------------------------------------------------------------- #
    # Public API
    # --------------------------------------------------------------------- #

    def auto_generate_tgt(
        self,
        *,
        username: str,
        credential: str,
        domain: str,
        workspace_dir: str,
        dc_ip: Optional[str] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> KerberosTGTResult:
        """Generate a Kerberos TGT from a password or NTLM hash.

        The credential type detection mirrors the heuristic that used to
        live in ``adscan.py``:

        - NTLM hash: 32 or 65 hex characters (``LM:NT``) or ``LM:NT`` where
          the second part has length 32.
        - Any other value is treated as a password.

        Args:
            username: Username for authentication.
            credential: Password or NTLM hash.
            domain: Target domain name.
            workspace_dir: Workspace root directory where Kerberos artefacts
                (``kerberos/tickets``) will be stored.
            dc_ip: Optional Domain Controller IP address.

        Returns:
            KerberosTGTResult instance with operation outcome.
        """
        try:
            credential_path = str(credential or "").strip()
            if credential_path.lower().endswith(".ccache"):
                path_obj = Path(credential_path).expanduser()
                if path_obj.exists():
                    resolved_path = str(path_obj.resolve())
                    self.logger.debug(
                        "Reusing existing Kerberos ccache for %s@%s at %s",
                        username,
                        domain,
                        resolved_path,
                    )
                    return KerberosTGTResult(
                        username=username,
                        domain=domain,
                        ticket_path=resolved_path,
                        method="existing_ccache",
                        success=True,
                        error_message=None,
                    )
                return KerberosTGTResult(
                    username=username,
                    domain=domain,
                    ticket_path=None,
                    method="existing_ccache",
                    success=False,
                    error_message=f"Kerberos ccache not found: {credential_path}",
                )

            is_ntlm_hash = self._is_ntlm_credential(credential)

            if is_ntlm_hash:
                return self._create_tgt_from_ntlm(
                    username=username,
                    ntlm_hash=credential,
                    domain=domain,
                    workspace_dir=workspace_dir,
                    dc_ip=dc_ip,
                    posture_snapshot=posture_snapshot,
                )

            return self._create_tgt_from_password(
                username=username,
                password=credential,
                domain=domain,
                workspace_dir=workspace_dir,
                dc_ip=dc_ip,
                posture_snapshot=posture_snapshot,
            )

        except Exception as exc:  # pragma: no cover - protección de último recurso
            self.logger.exception(
                "Failed to auto-generate Kerberos TGT for %s@%s",
                username,
                domain,
                exc_info=True,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="auto",
                success=False,
                error_message=str(exc),
            )

    def create_tgt_from_kerberos_key_material(
        self,
        *,
        material: KerberosKeyMaterial,
        domain: str,
        workspace_dir: str,
        dc_ip: Optional[str] = None,
    ) -> KerberosTGTResult:
        """Generate a TGT from typed Kerberos key material.

        AES256 is preferred over AES128, with NT/RC4 as fallback. This keeps
        modern Kerberos key material out of the legacy password/NTLM credential
        map while still making it usable by ticket-dependent workflows.
        """
        selected = CredentialStoreService.select_best_kerberos_key(material)
        if selected is None:
            return KerberosTGTResult(
                username=material.username,
                domain=domain,
                ticket_path=None,
                method="kerberos_key",
                success=False,
                error_message="No reusable Kerberos key material available",
            )
        key_kind, key_value = selected
        if key_kind == "nt_hash":
            return self._create_tgt_from_ntlm(
                username=material.username,
                ntlm_hash=key_value,
                domain=domain,
                workspace_dir=workspace_dir,
                dc_ip=dc_ip,
            )
        return self._create_tgt_from_aes_key(
            username=material.username,
            aes_key=key_value,
            key_kind=key_kind,
            domain=domain,
            workspace_dir=workspace_dir,
            dc_ip=dc_ip,
        )

    def setup_environment_for_domain(
        self,
        *,
        workspace_dir: str,
        domain: str,
        user_domain: str,
        username: Optional[str] = None,
        domains_data: Optional[Mapping[str, Any]] = None,
    ) -> tuple[bool, bool, Optional[str], Optional[str]]:
        """Set up KRB5_CONFIG and KRB5CCNAME for a given domain/user.

        This mirrors ``_setup_kerberos_environment_for_domain`` from ``adscan.py``
        but is expressed as a reusable service helper without any CLI output.

        Args:
            workspace_dir: Workspace root directory.
            domain: Target domain.
            user_domain: Domain used to look up stored tickets (may differ in
                some multi-domain scenarios).
            username: Optional username to locate a ticket for.
            domains_data: Optional mapping with per-domain state that may
                contain a ``\"kerberos_tickets\"`` dictionary.

        Returns:
            Tuple ``(krb5_config_set, kerberos_ticket_set, krb5_config_path, ticket_path)``.
        """
        krb5_config_set = False
        kerberos_ticket_set = False
        krb5_config_path: Optional[str] = None
        ticket_path: Optional[str] = None

        try:
            # 1) Configure KRB5_CONFIG to use the unified krb5.conf in the workspace
            krb5_conf = Path(workspace_dir).expanduser().resolve() / "krb5.conf"
            if krb5_conf.exists():
                os.environ["KRB5_CONFIG"] = str(krb5_conf)
                krb5_config_set = True
                krb5_config_path = str(krb5_conf)
                self.logger.debug("Using workspace krb5.conf at %s", krb5_conf)
            else:
                self.logger.warning(
                    "No krb5.conf found for domain %s at %s", domain, krb5_conf
                )

            # 2) Configure KRB5CCNAME for the chosen user (if provided)
            if username:
                ticket_path = self.get_ticket_for_user(
                    workspace_dir=workspace_dir,
                    domain=user_domain,
                    username=username,
                    domains_data=domains_data,
                )
                if ticket_path and Path(ticket_path).exists():
                    os.environ["KRB5CCNAME"] = ticket_path
                    kerberos_ticket_set = True
                    self.logger.debug("KRB5CCNAME set to %s", ticket_path)
                else:
                    self.logger.info(
                        "No Kerberos ticket found for %s@%s", username, domain
                    )
            else:
                self.logger.debug(
                    "No username provided for Kerberos ticket setup for domain %s",
                    domain,
                )

            return krb5_config_set, kerberos_ticket_set, krb5_config_path, ticket_path

        except Exception:
            self.logger.exception(
                "Error setting up Kerberos environment for domain %s", domain
            )
            return krb5_config_set, kerberos_ticket_set, krb5_config_path, ticket_path

    def validate_environment(
        self,
        *,
        username: Optional[str] = None,
    ) -> KerberosEnvironmentStatus:
        """Validate current process Kerberos environment.

        This is a direct service equivalent of ``_validate_kerberos_environment``
        from ``adscan.py`` and inspects the active process environment
        variables.
        """
        status = KerberosEnvironmentStatus()

        try:
            # Check KRB5_CONFIG
            krb5_config_path = os.environ.get("KRB5_CONFIG")
            if krb5_config_path and os.path.exists(krb5_config_path):
                status.krb5_config_ready = True
                status.krb5_config_path = krb5_config_path
            else:
                status.issues.append(
                    f"KRB5_CONFIG not set or file not found: {krb5_config_path}"
                )

            # Check KRB5CCNAME if username provided
            if username:
                ticket_path = os.environ.get("KRB5CCNAME")
                if ticket_path and os.path.exists(ticket_path):
                    status.kerberos_ticket_ready = True
                    status.ticket_path = ticket_path
                else:
                    status.issues.append(
                        f"KRB5CCNAME not set or ticket file not found: {ticket_path}"
                    )

            if status.krb5_config_ready and (
                not username or status.kerberos_ticket_ready
            ):
                status.ready_for_kerberos_commands = True

        except Exception as exc:  # pragma: no cover - defensive
            status.issues.append(f"Validation error: {exc}")
            self.logger.exception(
                "Error validating Kerberos environment", exc_info=True
            )

        return status

    def get_ticket_for_user(
        self,
        *,
        workspace_dir: str,
        domain: str,
        username: str,
        domains_data: Optional[Mapping[str, Any]] = None,
    ) -> Optional[str]:
        """Return ticket path for a specific user in a domain, if any.

        This helper mirrors ``_get_kerberos_ticket_for_user`` from ``adscan.py``.
        """
        # 1) Try domains_data mapping first (backwards compatibility with CLI)
        try:
            if domains_data and domain in domains_data:
                kerberos_tickets = domains_data[domain].get("kerberos_tickets", {})
                if username in kerberos_tickets:
                    return kerberos_tickets.get(username)
        except Exception:
            self.logger.debug(
                "Error reading kerberos_tickets from domains_data for %s@%s",
                username,
                domain,
            )

        # 2) Fallback to file system layout
        try:
            ticket_path = (
                Path(workspace_dir).expanduser().resolve()
                / "domains"
                / domain
                / "kerberos"
                / "tickets"
                / f"{username}.ccache"
            )
            if ticket_path.exists():
                return str(ticket_path)
        except Exception:
            self.logger.debug(
                "Error resolving Kerberos ticket path for %s@%s", username, domain
            )

        return None

    def is_ticket_valid(self, *, ticket_path: str) -> bool | None:
        """Return True if the provided ccache appears valid (best-effort).

        We rely on ``klist -s -c <ticket>`` as the primary validation path
        because ``klist -c`` may still return success while listing expired
        tickets. The ``-s`` mode is intended for scripting and reports whether
        the cache is currently usable.

        Returns:
            - True: the cache appears readable and currently usable
            - False: the cache is missing, unreadable, or expired
            - None: unable to validate (klist not available or unexpected error)
        """
        path = str(ticket_path or "").strip()
        if not path:
            return False

        try:
            if not Path(path).exists():
                return False
        except Exception:
            return False

        try:
            clean_env = get_clean_env_for_compilation()
            silent_proc = self._run_command_logged(
                label="klist -s -c",
                command=["klist", "-s", "-c", path],
                env=clean_env,
                shell=False,
            )
            if silent_proc.returncode == 0:
                return True
            fallback_proc = self._run_command_logged(
                label="klist -c",
                command=["klist", "-c", path],
                env=clean_env,
                shell=False,
            )
            if fallback_proc.returncode == 0:
                stderr_text = str(fallback_proc.stderr or "").strip().lower()
                if "unknown option" in stderr_text or "usage:" in stderr_text:
                    return None
            return False
        except FileNotFoundError:
            return None
        except Exception:
            self.logger.debug(
                "Unexpected error validating Kerberos ticket via klist (path=%s)",
                path,
                exc_info=True,
            )
            return None

    def try_renew_tgt(self, *, ticket_path: str) -> bool:
        """Attempt to renew an expired or soon-to-expire TGT in-place.

        Uses ``kinit -R -c <path>`` which asks the KDC to issue a refreshed
        TGT against the same ccache file.  This only works when:
        - The original TGT had the RENEWABLE flag set.
        - The current time is within the ``renew_till`` window.

        Kerberos TGTs on Windows domains typically have a 7-day renewable
        window even if the initial validity is only 10 hours — so renewal
        succeeds for sessions that last up to a week.

        Returns:
            True if the TGT was successfully renewed and the ccache is now valid.
            False if renewal failed (expired beyond renew_till, kinit absent,
            or any other error).  The caller should fall back to re-requesting
            a fresh TGT or to password/NTLM auth.
        """
        path = str(ticket_path or "").strip()
        if not path:
            return False
        try:
            if not Path(path).exists():
                return False
        except Exception:
            return False

        try:
            clean_env = get_clean_env_for_compilation()
            clean_env["KRB5CCNAME"] = path
            proc = self._run_command_logged(
                label="kinit -R",
                command=["kinit", "-R", "-c", path],
                env=clean_env,
                shell=False,
            )
            if proc.returncode == 0:
                self.logger.info(
                    "Kerberos TGT renewed successfully (ccache=%s)", path
                )
                return True
            self.logger.debug(
                "kinit -R failed for %s (rc=%s): %s",
                path,
                proc.returncode,
                str(proc.stderr or proc.stdout or "").strip()[:200],
            )
            return False
        except FileNotFoundError:
            self.logger.debug("kinit not available — cannot renew TGT")
            return False
        except Exception:
            self.logger.debug(
                "Unexpected error renewing TGT (path=%s)", path, exc_info=True
            )
            return False

    # --------------------------------------------------------------------- #
    # Internal helpers
    # --------------------------------------------------------------------- #

    @staticmethod
    def _is_ntlm_credential(credential: str) -> bool:
        """Heuristic check to determine if a credential looks like an NTLM hash."""
        # 32 or 65 chars (LM:NT) of hex + optional colon
        if len(credential) in (32, 65) and all(
            c in "0123456789abcdefABCDEF:" for c in credential
        ):
            return True
        if ":" in credential and len(credential.split(":", 1)[1]) == 32:
            return True
        return False

    @staticmethod
    def _build_ccache_dir(workspace_dir: str, domain: str) -> Path:
        """Return ccache directory for a given workspace and domain."""
        root = Path(workspace_dir).expanduser().resolve()
        ccache_dir = root / "domains" / domain / "kerberos" / "tickets"
        ccache_dir.mkdir(parents=True, exist_ok=True)
        return ccache_dir

    @classmethod
    def _build_ccache_paths(
        cls, *, workspace_dir: str, domain: str, username: str
    ) -> tuple[Path, Path]:
        """Return (final_path, temp_path) to create/refresh ccache safely.

        We write into a temp file first and replace the final ticket only once the
        operation succeeds. This avoids clobbering a working ticket when a refresh
        attempt fails.
        """
        ccache_dir = cls._build_ccache_dir(workspace_dir, domain)
        final_path = ccache_dir / f"{username}.ccache"
        nonce = f"{int(time.time())}-{os.getpid()}"
        temp_path = ccache_dir / f".{username}.{nonce}.ccache.tmp"
        return final_path, temp_path

    @staticmethod
    def _finalize_ticket_file(*, temp_path: Path, final_path: Path) -> bool:
        """Atomically replace final ticket with temp ticket (best-effort)."""
        try:
            if not temp_path.exists():
                return False
            final_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path.replace(final_path)
            return True
        except Exception:
            return False

    @staticmethod
    def _safe_file_size(path: Path) -> int | None:
        """Return file size in bytes when possible, otherwise ``None``."""
        try:
            return path.stat().st_size if path.exists() else None
        except Exception:
            return None

    def _log_ticket_paths_state(
        self,
        *,
        temp_path: Path,
        final_path: Path,
        default_path: Path,
    ) -> None:
        """Log ticket artifact state to debug missing/partial generation issues."""
        self.logger.debug(
            (
                "Ticket artifact state: temp=%s (exists=%s,size=%s), "
                "final=%s (exists=%s,size=%s), "
                "default=%s (exists=%s,size=%s), cwd=%s"
            ),
            temp_path,
            temp_path.exists(),
            self._safe_file_size(temp_path),
            final_path,
            final_path.exists(),
            self._safe_file_size(final_path),
            default_path,
            default_path.exists(),
            self._safe_file_size(default_path),
            Path.cwd(),
        )

    def _run_command_logged(
        self,
        *,
        label: str,
        command: str | list[str],
        timeout: int | None = None,
        env: Mapping[str, str] | None = None,
        shell: bool = False,
        cwd: str | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run command with centralized debug summary and output preview."""
        self.logger.debug("%s command: %s", label, command)
        result = self._command_runner.run(
            CommandSpec(
                command=command,
                timeout=timeout,
                shell=shell,
                capture_output=True,
                text=True,
                check=False,
                env=env,
                cwd=cwd,
                input=input_text,
            )
        )

        exit_code, stdout_count, stderr_count, duration_text = (
            summarize_execution_result(result)
        )
        self.logger.debug(
            "%s result: exit_code=%s, stdout_lines=%s, stderr_lines=%s, duration=%s",
            label,
            exit_code,
            stdout_count,
            stderr_count,
            duration_text,
        )
        preview = build_execution_output_preview(result)
        if preview:
            self.logger.debug("%s output preview:\n%s", label, preview)
        return result

    def _setup_domain_krb5_config(
        self,
        *,
        workspace_dir: str,
        domain: str,
    ) -> Optional[Path]:
        """Set KRB5_CONFIG to a domain-specific krb5.conf if present.

        Busca el fichero en::

            <workspace_dir>/domains/<domain>/krb5conf/krb5.conf

        Args:
            workspace_dir: Workspace root directory.
            domain: Domain name.

        Returns:
            Path to krb5.conf if found, otherwise None.
        """
        root = Path(workspace_dir).expanduser().resolve()
        krb5_conf_path = root / "domains" / domain / "krb5conf" / "krb5.conf"

        if krb5_conf_path.exists():
            os.environ["KRB5_CONFIG"] = str(krb5_conf_path)
            self.logger.debug("Using domain-specific krb5.conf at %s", krb5_conf_path)
            return krb5_conf_path

        self.logger.debug(
            "No domain-specific krb5.conf found for %s under %s",
            domain,
            root,
        )
        return None

    # ------------------------------------------------------------------ #
    # TGT from password
    # ------------------------------------------------------------------ #

    def _create_tgt_from_password(
        self,
        *,
        username: str,
        password: str,
        domain: str,
        workspace_dir: str,
        dc_ip: Optional[str],
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> KerberosTGTResult:
        """Create a Kerberos TGT using password-based authentication.

        Tries the native kerbad async stack first. Falls back to kinit when
        kerbad raises (e.g. complex password characters, non-standard KDC).
        """
        self._setup_domain_krb5_config(workspace_dir=workspace_dir, domain=domain)

        final_ccache_path, _ = self._build_ccache_paths(
            workspace_dir=workspace_dir,
            domain=domain,
            username=username,
        )

        self.logger.info(
            "Creating Kerberos TGT for %s@%s using native kerbad stack",
            username,
            domain,
        )

        try:
            ccache_bytes = self._kerbad_get_tgt_password(
                username=username,
                password=password,
                domain=domain,
                dc_ip=dc_ip,
                posture_snapshot=posture_snapshot,
            )
            _write_ccache_bytes(ccache_bytes, final_ccache_path)
            os.environ["KRB5CCNAME"] = str(final_ccache_path)
            self.logger.info(
                "Kerberos TGT created for %s@%s at %s",
                username,
                domain,
                final_ccache_path,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=str(final_ccache_path),
                method="kerberos_password",
                success=True,
            )
        except Exception as exc:
            self.logger.warning(
                "Native kerbad TGT failed for %s@%s (%s), falling back to kinit",
                username,
                domain,
                exc,
            )

        return self._create_tgt_with_kinit(
            username=username,
            password=password,
            domain=domain,
            workspace_dir=workspace_dir,
            dc_ip=dc_ip,
        )

    @staticmethod
    def _kerbad_get_tgt_password(
        *,
        username: str,
        password: str,
        domain: str,
        dc_ip: Optional[str],
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> bytes:
        """Request a TGT via kerbad native async stack and return ccache bytes."""
        from adscan_internal.services.async_bridge import run_async_sync
        from adscan_internal.services.kerberos_transport import KerberosConfig, get_tgt

        config = KerberosConfig(
            domain=domain,
            kdc_ip=dc_ip or domain,
            username=username,
            password=password,
            posture_snapshot=posture_snapshot,
        )
        return run_async_sync(get_tgt(config))

    def _create_tgt_with_kinit(
        self,
        *,
        username: str,
        password: str,
        domain: str,
        workspace_dir: str,
        dc_ip: Optional[str],
    ) -> KerberosTGTResult:
        """Create TGT using kinit (krb5-user)."""
        self._setup_domain_krb5_config(workspace_dir=workspace_dir, domain=domain)

        # Asegurar que kinit está disponible (y krb5-user instalado)
        if shutil.which("kinit") is None:
            self.logger.info("Installing krb5-user for Kerberos authentication")
            clean_env = get_clean_env_for_compilation()
            try:
                install_result = self._run_command_logged(
                    label="apt-get install krb5-user",
                    command=["apt-get", "install", "-y", "krb5-user"],
                    env=clean_env,
                    shell=False,
                )
                if install_result.returncode != 0:
                    return KerberosTGTResult(
                        username=username,
                        domain=domain,
                        ticket_path=None,
                        method="kinit",
                        success=False,
                        error_message=(
                            (install_result.stderr or "").strip()
                            or "Failed to install krb5-user"
                        ),
                    )
            except Exception as exc:  # pragma: no cover - dependencia de sistema
                self.logger.exception(
                    "Failed to install krb5-user: %s", exc, exc_info=True
                )
                return KerberosTGTResult(
                    username=username,
                    domain=domain,
                    ticket_path=None,
                    method="kinit",
                    success=False,
                    error_message=f"Failed to install krb5-user: {exc}",
                )

        final_ccache_path, temp_ccache_path = self._build_ccache_paths(
            workspace_dir=workspace_dir,
            domain=domain,
            username=username,
        )

        krb5_conf_backup: Optional[Path] = None
        krb5_conf_path = Path("/etc/krb5.conf")

        try:
            if dc_ip:
                if krb5_conf_path.exists():
                    krb5_conf_backup = krb5_conf_path.with_suffix(".backup")
                    shutil.copy2(krb5_conf_path, krb5_conf_backup)

                krb5_content = (
                    "[libdefaults]\n"
                    f"    default_realm = {domain.upper()}\n\n"
                    "[realms]\n"
                    f"    {domain.upper()} = {{\n"
                    f"        kdc = {dc_ip}\n"
                    f"        admin_server = {dc_ip}\n"
                    "    }\n\n"
                    "[domain_realm]\n"
                    f"    .{domain} = {domain.upper()}\n"
                    f"    {domain} = {domain.upper()}\n"
                )
                krb5_conf_path.write_text(krb5_content, encoding="utf-8")

            kinit_cmd = ["kinit", f"{username}@{domain.upper()}"]
            self.logger.info(
                "Creating Kerberos TGT for %s@%s using kinit", username, domain
            )
            env = get_clean_env_for_compilation()
            env["KRB5CCNAME"] = str(temp_ccache_path)
            # Preserve any KRB5_CONFIG set by _setup_domain_krb5_config.
            if os.environ.get("KRB5_CONFIG"):
                env["KRB5_CONFIG"] = os.environ["KRB5_CONFIG"]

            result = self._run_command_logged(
                label="kinit",
                command=kinit_cmd,
                env=env,
                shell=False,
                input_text=password,
            )

            if result.returncode == 0:
                if not self._finalize_ticket_file(
                    temp_path=temp_ccache_path, final_path=final_ccache_path
                ):
                    self._log_ticket_paths_state(
                        temp_path=temp_ccache_path,
                        final_path=final_ccache_path,
                        default_path=Path.cwd() / f"{username}.ccache",
                    )
                    return KerberosTGTResult(
                        username=username,
                        domain=domain,
                        ticket_path=None,
                        method="kinit",
                        success=False,
                        error_message="Ticket file was not created as expected",
                    )
                os.environ["KRB5CCNAME"] = str(final_ccache_path)
                self.logger.info(
                    "Kerberos TGT created successfully for %s@%s at %s",
                    username,
                    domain,
                    final_ccache_path,
                )
                return KerberosTGTResult(
                    username=username,
                    domain=domain,
                    ticket_path=str(final_ccache_path),
                    method="kinit",
                    success=True,
                )

            stderr_text = (result.stderr or "").strip()
            self.logger.warning(
                "kinit failed for %s@%s: %s",
                username,
                domain,
                stderr_text,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="kinit",
                success=False,
                error_message=stderr_text if stderr_text else "kinit failed",
            )

        finally:
            # Restaurar krb5.conf si se modificó
            if krb5_conf_backup and krb5_conf_backup.exists():
                try:
                    shutil.move(str(krb5_conf_backup), str(krb5_conf_path))
                except Exception:
                    self.logger.exception(
                        "Failed to restore original krb5.conf from backup %s",
                        krb5_conf_backup,
                    )

    # ------------------------------------------------------------------ #
    # TGT from Kerberos AES key
    # ------------------------------------------------------------------ #

    def _create_tgt_from_aes_key(
        self,
        *,
        username: str,
        aes_key: str,
        key_kind: str,
        domain: str,
        workspace_dir: str,
        dc_ip: Optional[str],
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> KerberosTGTResult:
        """Create a Kerberos TGT using AES key material via kerbad native stack."""
        self._setup_domain_krb5_config(workspace_dir=workspace_dir, domain=domain)

        final_ccache_path, _ = self._build_ccache_paths(
            workspace_dir=workspace_dir,
            domain=domain,
            username=username,
        )

        expected_len = 64 if key_kind == "aes256" else 32
        clean_aes_key = str(aes_key or "").strip().lower()
        if len(clean_aes_key) != expected_len or not re.fullmatch(
            r"[0-9a-f]+", clean_aes_key
        ):
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method=f"kerberos_{key_kind}",
                success=False,
                error_message=f"Invalid {key_kind} key format",
            )

        self.logger.info(
            "Creating Kerberos TGT from %s key for %s@%s",
            key_kind,
            username,
            domain,
        )

        try:
            from adscan_internal.services.async_bridge import run_async_sync
            from adscan_internal.services.kerberos_transport import (
                KerberosConfig,
                get_tgt,
            )

            config = KerberosConfig(
                domain=domain,
                kdc_ip=dc_ip or domain,
                username=username,
                aes_key=clean_aes_key,
                posture_snapshot=posture_snapshot,
            )
            ccache_bytes = run_async_sync(get_tgt(config))
        except Exception as exc:
            self.logger.warning(
                "kerbad TGT failed for %s key %s@%s: %s",
                key_kind,
                username,
                domain,
                exc,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method=f"kerberos_{key_kind}",
                success=False,
                error_message=str(exc),
            )

        try:
            _write_ccache_bytes(ccache_bytes, final_ccache_path)
        except Exception as exc:
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method=f"kerberos_{key_kind}",
                success=False,
                error_message=f"Failed to write ccache: {exc}",
            )

        os.environ["KRB5CCNAME"] = str(final_ccache_path)
        self.logger.info(
            "Kerberos TGT created for %s@%s at %s",
            username,
            domain,
            final_ccache_path,
        )
        return KerberosTGTResult(
            username=username,
            domain=domain,
            ticket_path=str(final_ccache_path),
            method=f"kerberos_{key_kind}",
            success=True,
        )

    # ------------------------------------------------------------------ #
    # TGT from NTLM hash
    # ------------------------------------------------------------------ #

    def _create_tgt_from_ntlm(
        self,
        *,
        username: str,
        ntlm_hash: str,
        domain: str,
        workspace_dir: str,
        dc_ip: Optional[str],
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> KerberosTGTResult:
        """Create a Kerberos TGT from an NT hash via kerbad native stack.

        Detects KDC_ERR_ETYPE_NOTSUPP (RC4 disabled by KDC policy) and returns
        error_kind="rc4_disabled" so callers can persist this as domain auth posture.
        """
        self._setup_domain_krb5_config(workspace_dir=workspace_dir, domain=domain)
        final_ccache_path, _ = self._build_ccache_paths(
            workspace_dir=workspace_dir,
            domain=domain,
            username=username,
        )

        # Normalize to NT part only (kerbad +nt URL expects 32 hex chars)
        if ":" in ntlm_hash:
            _, nt_part = ntlm_hash.split(":", 1)
        else:
            nt_part = ntlm_hash

        try:
            bytes.fromhex(nt_part)
            if len(nt_part) != 32:
                raise ValueError("NT hash must be exactly 32 hex chars")
        except ValueError:
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="kerberos_ntlm",
                success=False,
                error_message="Invalid NTLM hash format",
            )

        self.logger.info(
            "Creating Kerberos TGT from NT hash for %s@%s",
            username,
            domain,
        )

        try:
            from adscan_internal.services.async_bridge import run_async_sync
            from adscan_internal.services.kerberos_transport import (
                KerberosConfig,
                KerberosEtypeError,
                get_tgt,
            )

            config = KerberosConfig(
                domain=domain,
                kdc_ip=dc_ip or domain,
                username=username,
                nt_hash=nt_part,
                posture_snapshot=posture_snapshot,
            )
            ccache_bytes = run_async_sync(get_tgt(config))
        except KerberosEtypeError as exc:
            self.logger.warning(
                "KDC rejected RC4 for %s@%s (KDC_ERR_ETYPE_NOTSUPP) — "
                "domain requires AES; NT hash cannot authenticate via Kerberos.",
                username,
                domain,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="kerberos_ntlm",
                success=False,
                error_message=f"KDC_ERR_ETYPE_NOTSUPP: domain requires AES, NT hash cannot use Kerberos: {exc}",
                error_kind="rc4_disabled",
            )
        except Exception as exc:
            self.logger.warning(
                "Kerberos TGT request failed for %s@%s: %s",
                username,
                domain,
                exc,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="kerberos_ntlm",
                success=False,
                error_message=str(exc),
            )

        try:
            ticket_path = _write_ccache_bytes(ccache_bytes, final_ccache_path)
        except Exception as exc:
            self.logger.exception(
                "Failed to write ccache for %s@%s",
                username,
                domain,
                exc_info=True,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="kerberos_ntlm",
                success=False,
                error_message=f"Failed to write ccache: {exc}",
            )

        os.environ["KRB5CCNAME"] = ticket_path
        self.logger.info(
            "Kerberos TGT created for %s@%s at %s",
            username,
            domain,
            ticket_path,
        )
        return KerberosTGTResult(
            username=username,
            domain=domain,
            ticket_path=ticket_path,
            method="kerberos_ntlm",
            success=True,
        )

    # ------------------------------------------------------------------ #
    # Service tickets / S4U helpers
    # ------------------------------------------------------------------ #

    def create_forwardable_ticket_native(
        self,
        *,
        domain: str,
        pdc_hostname: str,
        pdc_ip: str,
        target_user: str,
        s4u_account: str,
        s4u_password: str,
        service: str = "browser",
    ) -> "KerberosServiceTicketResult":
        """Create a forwardable service ticket via native kerbad S4U2Self + S4U2Proxy.

        Replaces the getST.py subprocess call. The ccache is saved using the same
        naming convention as impacket so downstream flows (launch_s4proxy) can
        locate it without changes.

        Args:
            domain:       Target domain FQDN.
            pdc_hostname: PDC hostname (used for SPN and ccache filename).
            pdc_ip:       PDC IP (KDC address).
            target_user:  Privileged account to impersonate via S4U2Self.
            s4u_account:  Delegating account (computer$ or user) with S4U rights.
            s4u_password: Password for *s4u_account*.
            service:      SPN service class (default ``browser``).

        Returns:
            :class:`KerberosServiceTicketResult` with ``ticket_path`` on success.
        """
        from adscan_internal.services.async_bridge import run_async_sync

        spn = f"{service}/{pdc_hostname}.{domain}"
        ccache_filename = (
            f"{target_user}@{service}_{pdc_hostname}.{domain}@{domain.upper()}.ccache"
        )
        ccache_path = Path.cwd() / ccache_filename

        _render_s4u_preflight(
            domain=domain,
            kdc_ip=pdc_ip,
            s4u_account=s4u_account,
            target_user=target_user,
            spn=spn,
            ccache_path=str(ccache_path),
        )

        try:
            return run_async_sync(
                _s4u_forwardable_ticket_async(
                    domain=domain,
                    pdc_ip=pdc_ip,
                    s4u_account=s4u_account,
                    s4u_password=s4u_password,
                    target_user=target_user,
                    spn=spn,
                    ccache_path=ccache_path,
                )
            )
        except Exception as exc:
            from adscan_internal import telemetry as _tel  # noqa: PLC0415

            _tel.capture_exception(exc)
            msg = _classify_s4u_error(str(exc))
            print_error(f"S4U forwardable ticket failed: {msg}")
            return KerberosServiceTicketResult(
                target_user=target_user, spn=spn, success=False, error_message=msg
            )

    def sync_clock_with_pdc(
        self,
        pdc_ip: str,
        *,
        domain: str,
        is_full_container_runtime: Callable[[], bool],
        sudo_validate: Callable[[], bool],
        is_ntp_service_available: Callable[[str, int], bool],
        is_tcp_port_open: Callable[[str, int, int], bool],
        run_command: Callable[[str, int | None], Any],
        sync_clock_via_net_time: Callable[[str, str | None], bool],
        scan_id: Optional[str] = None,
        verbose: bool = False,
    ) -> bool:
        """Synchronize local system clock with PDC.

        DEPRECATED — do NOT call from new code. The single source of truth for
        physical clock sync is ``ensure_clock_synced_fresh`` in
        ``adscan_internal.services.dc_time`` (reached via the shell entry
        ``do_sync_clock_with_pdc`` → ``cli.kerberos.sync_clock_with_pdc``). This
        callback-based variant is retained only for backward compatibility and
        has no remaining in-tree callers; route new physical-sync needs through
        the SSOT so there is exactly one implementation.

        This method encapsulates the clock synchronization logic, accepting shell
        helpers as callbacks to maintain separation of concerns.

        Args:
            pdc_ip: Primary Domain Controller IP address.
            domain: Domain name for context and error messages.
            is_full_container_runtime: Callback to check if running in container.
            sudo_validate: Callback to validate sudo availability.
            is_ntp_service_available: Callback to check NTP service availability.
            is_tcp_port_open: Callback to check if TCP port is open.
            run_command: Callback to execute shell commands.
            sync_clock_via_net_time: Callback to sync via RPC/net time.
            scan_id: Optional scan ID for progress tracking.
            verbose: Whether to emit verbose messages.

        Returns:
            True if clock synchronization succeeded, False otherwise.
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="clock_sync",
            progress=0.0,
            message=f"Synchronizing clock with PDC {pdc_ip}",
        )

        # Validate domain format
        if (
            not domain
            or "." not in domain
            or not domain.replace(".", "").replace("-", "").isalnum()
        ):
            if verbose:
                self.logger.warning(
                    "Invalid domain format: %s",
                    domain,
                    extra={"domain": domain},
                )
            self._emit_progress(
                scan_id=scan_id,
                phase="clock_sync",
                progress=1.0,
                message="Clock sync failed: invalid domain format",
            )
            return False

        # Container runtime path
        if is_full_container_runtime():
            sock_path = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
            if not sock_path:
                if verbose:
                    self.logger.warning(
                        "Host helper socket not available",
                        extra={"domain": domain},
                    )
                self._emit_progress(
                    scan_id=scan_id,
                    phase="clock_sync",
                    progress=1.0,
                    message="Clock sync failed: host helper unavailable",
                )
                return False

            try:
                from adscan_internal.host_privileged_helper import (
                    HostHelperError,
                    host_helper_client_request,
                )

                # Disable NTP once per session
                if not getattr(self, "_host_ntp_disabled_once", False):
                    ntp_off_resp = host_helper_client_request(
                        sock_path,
                        op="timedatectl_set_ntp",
                        payload={"value": False},
                    )
                    if not ntp_off_resp.ok:
                        self.logger.warning("Could not disable NTP via timedatectl")
                    setattr(self, "_host_ntp_disabled_once", True)

                # Try NTP sync via host helper
                ntp_resp = host_helper_client_request(
                    sock_path, op="ntpdate", payload={"host": pdc_ip}
                )

                if ntp_resp.ok:
                    self.logger.info(
                        "Clock synchronized successfully via host helper",
                        extra={"pdc_ip": pdc_ip, "domain": domain},
                    )
                    self._emit_progress(
                        scan_id=scan_id,
                        phase="clock_sync",
                        progress=1.0,
                        message="Clock synchronized successfully",
                    )
                    return True

                # Fallback: try container NTP
                ntp_cmd = None
                if shutil.which("ntpdate"):
                    ntp_cmd = f"sudo -n ntpdate {pdc_ip}"
                elif shutil.which("ntpdig"):
                    ntp_cmd = f"sudo -n ntpdig -gq {pdc_ip}"

                if ntp_cmd:
                    proc = run_command(ntp_cmd, timeout=60)
                    if proc and getattr(proc, "returncode", None) == 0:
                        self.logger.info(
                            "Clock synchronized via container NTP fallback",
                            extra={"pdc_ip": pdc_ip, "domain": domain},
                        )
                        self._emit_progress(
                            scan_id=scan_id,
                            phase="clock_sync",
                            progress=1.0,
                            message="Clock synchronized successfully (fallback)",
                        )
                        return True

            except (HostHelperError, OSError):
                self.logger.exception(
                    "Host helper clock sync failed",
                    extra={"pdc_ip": pdc_ip, "domain": domain},
                    exc_info=True,
                )

            # Fallback: RPC-based sync
            if is_tcp_port_open(pdc_ip, 445):
                if sync_clock_via_net_time(pdc_ip, domain=domain):
                    self._emit_progress(
                        scan_id=scan_id,
                        phase="clock_sync",
                        progress=1.0,
                        message="Clock synchronized via RPC",
                    )
                    return True

            self._emit_progress(
                scan_id=scan_id,
                phase="clock_sync",
                progress=1.0,
                message="Clock sync failed",
            )
            return False

        # Non-container path
        needs_sudo = os.geteuid() != 0
        if needs_sudo and not sudo_validate():
            if verbose:
                self.logger.warning(
                    "Clock sync requires sudo but validation failed",
                    extra={"domain": domain},
                )
            self._emit_progress(
                scan_id=scan_id,
                phase="clock_sync",
                progress=1.0,
                message="Clock sync failed: sudo unavailable",
            )
            return False

        # Disable system NTP once per session
        timedatectl_cmd = "timedatectl set-ntp false"
        if needs_sudo:
            timedatectl_cmd = f"sudo -n {timedatectl_cmd}"
        if not getattr(self, "_system_ntp_disabled_once", False):
            run_command(timedatectl_cmd, timeout=300)
            setattr(self, "_system_ntp_disabled_once", True)

        max_ntpdig_attempts = 3
        try:
            ntp_available = is_ntp_service_available(pdc_ip)
            if ntp_available:
                ntpdate_cmd = f"ntpdate {pdc_ip}"
                if needs_sudo:
                    ntpdate_cmd = f"sudo -n {ntpdate_cmd}"

                attempt = 1
                while attempt <= max_ntpdig_attempts:
                    time.sleep(1)
                    process = run_command(ntpdate_cmd, timeout=300)
                    if process and getattr(process, "returncode", None) == 0:
                        self.logger.info(
                            "Clock synchronized successfully via NTP",
                            extra={"pdc_ip": pdc_ip, "domain": domain},
                        )
                        self._emit_progress(
                            scan_id=scan_id,
                            phase="clock_sync",
                            progress=1.0,
                            message="Clock synchronized successfully",
                        )
                        return True

                    error_output = ""
                    if process:
                        error_output = (getattr(process, "stderr", "") or "").strip()
                        if not error_output:
                            error_output = (
                                getattr(process, "stdout", "") or ""
                            ).strip()

                    if "operation not permitted" in (error_output or "").lower():
                        break

                    if (
                        "ntpdig: no eligible servers" in error_output
                        and attempt < max_ntpdig_attempts
                    ):
                        attempt += 1
                        continue

                    if error_output:
                        self.logger.warning(
                            "NTP sync error",
                            extra={
                                "pdc_ip": pdc_ip,
                                "domain": domain,
                                "error": error_output,
                            },
                        )
                    break
            else:
                self.logger.debug(
                    "NTP probe did not receive response, attempting RPC fallback",
                    extra={"pdc_ip": pdc_ip, "domain": domain},
                )

            # RPC fallback
            if is_tcp_port_open(pdc_ip, 445):
                if sync_clock_via_net_time(pdc_ip, domain=domain):
                    self._emit_progress(
                        scan_id=scan_id,
                        phase="clock_sync",
                        progress=1.0,
                        message="Clock synchronized via RPC",
                    )
                    return True

            self._emit_progress(
                scan_id=scan_id,
                phase="clock_sync",
                progress=1.0,
                message="Clock sync failed",
            )
            return False

        except Exception:
            self.logger.exception(
                "Clock synchronization error",
                extra={"pdc_ip": pdc_ip, "domain": domain},
                exc_info=True,
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="clock_sync",
                progress=1.0,
                message="Clock sync error",
            )
            return False


def ensure_user_ccache(
    shell: Any,
    *,
    user: str,
    domain: str,
    credential: Optional[str] = None,
    dc_ip: Optional[str] = None,
    force_refresh: bool = False,
    error_out: Optional[list] = None,
) -> Optional[str]:
    """Return path to a valid Kerberos ccache for ``user@domain``.

    This is the **single source of truth** every caller in the codebase
    should use when they need to authenticate as a specific principal
    via Kerberos. It replaces the historical pattern of passing
    ``username + password + kerberos=True`` and trusting that the LDAP
    transport will do the right thing — that pattern was the root cause
    of the 2026-05-21 ``KRB5CCNAME`` hijack on HTB Puppy (a follow-up
    ``enable_user`` ran with explicit ant.edwards credentials but the
    LDAP transport silently used LEVI.JAMES's ccache from the env var,
    rejecting the modify because LEVI.JAMES lacked GenericAll).

    Flow:

    1. Look up the canonical path
       ``<workspace>/domains/<domain>/kerberos/tickets/<user>.ccache``.
    2. If the file exists AND ``is_ticket_valid`` confirms it is usable,
       return the path (fast path — no AS-REQ).
    3. Otherwise mint a fresh TGT via :meth:`KerberosTicketService.auto_generate_tgt`
       using the supplied ``credential`` (or the one stored in the
       shell's credential registry under ``(domain, user)``), save it to
       the canonical path, and return the path.
    4. Update ``shell.domains_data[domain]["kerberos_tickets"][user]`` so
       subsequent callers find the path through the legacy registry too.

    Args:
        shell: PentestShell instance with ``workspace_dir``,
            ``domains_data`` and (optionally) a credential registry. Any
            object exposing these attributes works for tests.
        user: sAMAccountName of the principal to authenticate as.
        domain: Active Directory domain name.
        credential: Password or NTLM hash. If ``None``, the function
            looks up the credential in the shell's stored credentials.
            Pass explicitly when the caller already has the cleartext
            (e.g. immediately after spraying validates a password).
        dc_ip: Optional DC IP for the AS-REQ. Falls back to
            ``shell.domains_data[domain]["pdc"]`` when omitted.
        force_refresh: When ``True``, ignore any existing ccache and
            always mint a fresh TGT. Use after privilege-granting
            operations (AddMember, ForceChangePassword) so the next
            bind sees the updated PAC.
        error_out: Optional mutable list. When provided and the mint
            fails, the underlying ``error_message`` (or a short reason)
            is appended so the caller can classify the failure cause
            (e.g. DC-unreachable vs credential-invalid) instead of
            inferring it from a bare ``None``. Default ``None`` leaves
            behaviour unchanged for every existing caller.

    Returns:
        Path to a valid ccache, or ``None`` when minting failed and
        no usable cache exists. Callers must check for ``None`` and
        decide whether to fall back to password-based auth or surface
        an error to the operator.

    Notes:
        Idempotent and safe to call from any flow. The fast path is
        a single ``klist -s -c`` invocation when the cache exists and
        is valid — typically under 50ms.
    """
    user = (user or "").strip()
    domain = (domain or "").strip()
    if not user or not domain:
        print_info_debug(
            "[kerberos-auth] ensure_user_ccache: missing user or domain; "
            f"user={user!r} domain={domain!r}. Cannot mint TGT."
        )
        return None

    # The canonical attribute on ``PentestShell`` is ``current_workspace_dir``
    # — the other names are legacy aliases that some test shells / older
    # entry points still expose. Probe all of them so the helper works
    # uniformly across the shell variants in the codebase. A missing
    # attribute is no longer a silent return: we log it so the next
    # operator knows their shell didn't carry the workspace into the
    # Kerberos call.
    workspace_dir = str(
        getattr(shell, "current_workspace_dir", None)
        or getattr(shell, "workspace_dir", None)
        or getattr(shell, "workspace_path", None)
        or ""
    ).strip()
    if not workspace_dir:
        print_info_debug(
            "[kerberos-auth] ensure_user_ccache: shell exposes no "
            "current_workspace_dir/workspace_dir/workspace_path; cannot "
            f"locate the kerberos/tickets folder. user={mark_sensitive(user, 'user')} "
            f"domain={mark_sensitive(domain, 'domain')} shell_type={type(shell).__name__!r}"
        )
        return None

    domains_data = getattr(shell, "domains_data", None) or {}
    service = KerberosTicketService()

    if not force_refresh:
        cached_path = service.get_ticket_for_user(
            workspace_dir=workspace_dir,
            domain=domain,
            username=user,
            domains_data=domains_data,
        )
        if cached_path and service.is_ticket_valid(ticket_path=cached_path):
            return cached_path

    # Resolve the credential. Caller-supplied value wins; fall back to
    # the shell's credential store. We intentionally do not expose the
    # credential in any log line — only its presence/absence.
    resolved_credential = (credential or "").strip()
    if not resolved_credential:
        domain_record = (
            domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        )
        stored = domain_record.get("credentials", {}) if isinstance(
            domain_record, dict
        ) else {}
        if isinstance(stored, dict):
            entry = stored.get(user) or stored.get(user.lower()) or stored.get(
                user.upper()
            )
            if isinstance(entry, str):
                resolved_credential = entry.strip()
            elif isinstance(entry, dict):
                resolved_credential = str(
                    entry.get("password") or entry.get("hash") or ""
                ).strip()

    if not resolved_credential:
        print_info_debug(
            "[kerberos-auth] ensure_user_ccache: no credential available for "
            f"user={mark_sensitive(user, 'user')} "
            f"domain={mark_sensitive(domain, 'domain')}; cannot mint TGT."
        )
        return None

    # Resolve the DC IP for the AS-REQ.
    if not dc_ip:
        domain_record = (
            domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        )
        if isinstance(domain_record, dict):
            dc_ip = (
                domain_record.get("pdc")
                or (
                    domain_record.get("dcs")[0]
                    if isinstance(domain_record.get("dcs"), list)
                    and domain_record["dcs"]
                    else None
                )
            )

    result = service.auto_generate_tgt(
        username=user,
        credential=resolved_credential,
        domain=domain,
        workspace_dir=workspace_dir,
        dc_ip=dc_ip,
    )

    if not result.success or not result.ticket_path:
        print_info_debug(
            "[kerberos-auth] ensure_user_ccache: TGT mint failed for "
            f"user={mark_sensitive(user, 'user')} "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"error={result.error_message!r}"
        )
        if error_out is not None:
            error_out.append(result.error_message or "TGT mint failed")
        return None

    # Update the legacy registry so other code paths that consult
    # ``domains_data[domain]["kerberos_tickets"]`` see the fresh ticket.
    if isinstance(domains_data, dict):
        domain_record = domains_data.setdefault(domain, {})
        if isinstance(domain_record, dict):
            tickets = domain_record.setdefault("kerberos_tickets", {})
            if isinstance(tickets, dict):
                tickets[user] = result.ticket_path

    return result.ticket_path


__all__ = [
    "KerberosTicketService",
    "KerberosTGTResult",
    "KerberosServiceTicketResult",
    "ensure_user_ccache",
]
