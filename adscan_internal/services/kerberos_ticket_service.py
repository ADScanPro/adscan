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
from typing import Any, Callable, Mapping, Optional
import ipaddress
import os
import re
import shlex
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
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error_debug,
    print_info_debug,
    print_warning_debug,
)
from adscan_internal.services.credential_store_service import (
    CredentialStoreService,
    KerberosKeyMaterial,
)


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
                )

            return self._create_tgt_from_password(
                username=username,
                password=credential,
                domain=domain,
                workspace_dir=workspace_dir,
                dc_ip=dc_ip,
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
    ) -> KerberosTGTResult:
        """Create a Kerberos TGT using password-based authentication.

        Primero intenta usar el script ``getTGT.py`` de Impacket dentro del
        venv de Impacket, y si falla o no está disponible, hace fallback a
        ``kinit`` (paquete ``krb5-user``).
        """
        # Aseguramos KRB5_CONFIG si existe uno específico de dominio
        self._setup_domain_krb5_config(workspace_dir=workspace_dir, domain=domain)

        final_ccache_path, temp_ccache_path = self._build_ccache_paths(
            workspace_dir=workspace_dir,
            domain=domain,
            username=username,
        )

        # Intentar primero con impacket
        adscan_home = get_adscan_home()
        impacket_venv_path = adscan_home / "tool_venvs" / "impacket" / "venv"
        get_tgt_script = impacket_venv_path / "bin" / "getTGT.py"

        if not get_tgt_script.exists():
            self.logger.warning(
                "Impacket getTGT.py not found at %s, falling back to kinit",
                get_tgt_script,
            )
            return self._create_tgt_with_kinit(
                username=username,
                password=password,
                domain=domain,
                workspace_dir=workspace_dir,
                dc_ip=dc_ip,
            )

        env = get_clean_env_for_compilation()
        env["KRB5CCNAME"] = str(temp_ccache_path)

        identity = f"{domain}/{username}:{password}"
        cmd = [str(impacket_venv_path / "bin" / "python"), str(get_tgt_script)]
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        cmd.append(identity)

        self.logger.info(
            "Creating Kerberos TGT for %s@%s using Impacket getTGT.py",
            username,
            domain,
        )
        try:
            get_tgt_result = self._run_command_logged(
                label="getTGT.py",
                command=cmd,
                env=env,
                shell=False,
            )
        except Exception:  # pragma: no cover - error inesperado
            self.logger.exception(
                "Error running getTGT.py for %s@%s", username, domain, exc_info=True
            )
            return self._create_tgt_with_kinit(
                username=username,
                password=password,
                domain=domain,
                workspace_dir=workspace_dir,
                dc_ip=dc_ip,
            )

        if get_tgt_result.returncode != 0:
            self.logger.warning(
                "Impacket getTGT.py failed for %s@%s with exit code %s",
                username,
                domain,
                get_tgt_result.returncode,
            )
            # Fallback a kinit
            return self._create_tgt_with_kinit(
                username=username,
                password=password,
                domain=domain,
                workspace_dir=workspace_dir,
                dc_ip=dc_ip,
            )

        # Mover ccache a ubicación final si se creó en el cwd
        default_ccache = Path.cwd() / f"{username}.ccache"
        if default_ccache.exists():
            try:
                default_ccache.rename(temp_ccache_path)
            except Exception:
                self.logger.debug(
                    "Failed to move default ccache from cwd to temp path",
                    exc_info=True,
                )

        if not self._finalize_ticket_file(
            temp_path=temp_ccache_path, final_path=final_ccache_path
        ):
            self._log_ticket_paths_state(
                temp_path=temp_ccache_path,
                final_path=final_ccache_path,
                default_path=default_ccache,
            )
            self.logger.warning(
                "Impacket getTGT.py returned success but ticket file was not created; "
                "falling back to kinit for %s@%s",
                username,
                domain,
            )
            return self._create_tgt_with_kinit(
                username=username,
                password=password,
                domain=domain,
                workspace_dir=workspace_dir,
                dc_ip=dc_ip,
            )

        self._log_ticket_paths_state(
            temp_path=temp_ccache_path,
            final_path=final_ccache_path,
            default_path=default_ccache,
        )

        os.environ["KRB5CCNAME"] = str(final_ccache_path)

        self.logger.info(
            "Kerberos TGT created successfully for %s@%s using Impacket at %s",
            username,
            domain,
            final_ccache_path,
        )
        return KerberosTGTResult(
            username=username,
            domain=domain,
            ticket_path=str(final_ccache_path),
            method="impacket_password",
            success=True,
        )

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
    ) -> KerberosTGTResult:
        """Create a Kerberos TGT using AES key material and Impacket getTGT.py."""
        self._setup_domain_krb5_config(workspace_dir=workspace_dir, domain=domain)

        final_ccache_path, temp_ccache_path = self._build_ccache_paths(
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
                method=f"impacket_{key_kind}",
                success=False,
                error_message=f"Invalid {key_kind} key format",
            )

        adscan_home = get_adscan_home()
        impacket_venv_path = adscan_home / "tool_venvs" / "impacket" / "venv"
        get_tgt_script = impacket_venv_path / "bin" / "getTGT.py"
        if not get_tgt_script.exists():
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method=f"impacket_{key_kind}",
                success=False,
                error_message="getTGT.py not found for AES authentication",
            )

        env = get_clean_env_for_compilation()
        env["KRB5CCNAME"] = str(temp_ccache_path)

        identity = f"{domain}/{username}"
        cmd = [str(impacket_venv_path / "bin" / "python"), str(get_tgt_script)]
        cmd.extend(["-aesKey", clean_aes_key])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        cmd.append(identity)

        try:
            get_tgt_result = self._run_command_logged(
                label=f"getTGT.py {key_kind}",
                command=cmd,
                env=env,
                shell=False,
            )
        except Exception as exc:  # pragma: no cover - unexpected runtime error
            self.logger.exception(
                "Error running getTGT.py for AES key %s@%s",
                username,
                domain,
                exc_info=True,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method=f"impacket_{key_kind}",
                success=False,
                error_message=str(exc),
            )

        if get_tgt_result.returncode != 0:
            stderr_text = (get_tgt_result.stderr or "").strip()
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method=f"impacket_{key_kind}",
                success=False,
                error_message=stderr_text or "getTGT.py failed",
            )

        default_ccache = Path.cwd() / f"{username}.ccache"
        if default_ccache.exists():
            try:
                default_ccache.rename(temp_ccache_path)
            except Exception:
                self.logger.debug(
                    "Failed to move default ccache from cwd to temp path",
                    exc_info=True,
                )

        if not self._finalize_ticket_file(
            temp_path=temp_ccache_path, final_path=final_ccache_path
        ):
            self._log_ticket_paths_state(
                temp_path=temp_ccache_path,
                final_path=final_ccache_path,
                default_path=default_ccache,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method=f"impacket_{key_kind}",
                success=False,
                error_message="Ticket file was not created as expected",
            )

        self._log_ticket_paths_state(
            temp_path=temp_ccache_path,
            final_path=final_ccache_path,
            default_path=default_ccache,
        )
        os.environ["KRB5CCNAME"] = str(final_ccache_path)

        return KerberosTGTResult(
            username=username,
            domain=domain,
            ticket_path=str(final_ccache_path),
            method=f"impacket_{key_kind}",
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
    ) -> KerberosTGTResult:
        """Create a Kerberos TGT using NTLM hash and Impacket getTGT.py."""
        self._setup_domain_krb5_config(workspace_dir=workspace_dir, domain=domain)

        final_ccache_path, temp_ccache_path = self._build_ccache_paths(
            workspace_dir=workspace_dir,
            domain=domain,
            username=username,
        )

        adscan_home = get_adscan_home()
        impacket_venv_path = adscan_home / "tool_venvs" / "impacket" / "venv"
        get_tgt_script = impacket_venv_path / "bin" / "getTGT.py"
        if not get_tgt_script.exists():
            self.logger.warning(
                "Impacket getTGT.py not found at %s, cannot create TGT from NTLM hash",
                get_tgt_script,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="impacket_ntlm",
                success=False,
                error_message="getTGT.py not found for NTLM authentication",
            )

        # Parsear hash LM:NT o solo NT
        if ":" in ntlm_hash:
            lm_hash, nt_hash = ntlm_hash.split(":", 1)
        else:
            lm_hash = "aad3b435b51404eeaad3b435b51404ee"
            nt_hash = ntlm_hash

        try:
            bytes.fromhex(lm_hash)
            bytes.fromhex(nt_hash)
        except ValueError:
            self.logger.warning("Invalid NTLM hash format: %s", ntlm_hash)
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="impacket_ntlm",
                success=False,
                error_message="Invalid NTLM hash format",
            )

        env = get_clean_env_for_compilation()
        env["KRB5CCNAME"] = str(temp_ccache_path)

        identity = f"{domain}/{username}"
        cmd = [str(impacket_venv_path / "bin" / "python"), str(get_tgt_script)]
        cmd.extend(["-hashes", f"{lm_hash}:{nt_hash}"])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        cmd.append(identity)

        self.logger.info(
            "Creating Kerberos TGT from NTLM hash for %s@%s using Impacket getTGT.py",
            username,
            domain,
        )
        try:
            get_tgt_result = self._run_command_logged(
                label="getTGT.py NTLM",
                command=cmd,
                env=env,
                shell=False,
            )
        except Exception as exc:  # pragma: no cover - error inesperado
            self.logger.exception(
                "Error running getTGT.py for NTLM hash %s@%s",
                username,
                domain,
                exc_info=True,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="impacket_ntlm",
                success=False,
                error_message=str(exc),
            )

        if get_tgt_result.returncode != 0:
            stderr_text = (get_tgt_result.stderr or "").strip()
            self.logger.warning(
                "Failed to create Kerberos TGT from NTLM hash with getTGT.py "
                "for %s@%s (exit=%s)",
                username,
                domain,
                get_tgt_result.returncode,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="impacket_ntlm",
                success=False,
                error_message=stderr_text or "getTGT.py failed",
            )

        default_ccache = Path.cwd() / f"{username}.ccache"
        if default_ccache.exists():
            try:
                default_ccache.rename(temp_ccache_path)
            except Exception:
                self.logger.debug(
                    "Failed to move default ccache from cwd to temp path",
                    exc_info=True,
                )

        if not self._finalize_ticket_file(
            temp_path=temp_ccache_path, final_path=final_ccache_path
        ):
            self._log_ticket_paths_state(
                temp_path=temp_ccache_path,
                final_path=final_ccache_path,
                default_path=default_ccache,
            )
            return KerberosTGTResult(
                username=username,
                domain=domain,
                ticket_path=None,
                method="impacket_ntlm",
                success=False,
                error_message="Ticket file was not created as expected",
            )

        self._log_ticket_paths_state(
            temp_path=temp_ccache_path,
            final_path=final_ccache_path,
            default_path=default_ccache,
        )

        os.environ["KRB5CCNAME"] = str(final_ccache_path)

        self.logger.info(
            "Kerberos TGT from NTLM hash created successfully for %s@%s at %s",
            username,
            domain,
            final_ccache_path,
        )
        return KerberosTGTResult(
            username=username,
            domain=domain,
            ticket_path=str(final_ccache_path),
            method="impacket_ntlm",
            success=True,
        )

    # ------------------------------------------------------------------ #
    # Service tickets / S4U helpers (getST.py)
    # ------------------------------------------------------------------ #

    def create_forwardable_ticket(
        self,
        *,
        impacket_scripts_dir: str,
        domain: str,
        pdc_hostname: str,
        pdc_ip: str,
        target_user: str,
        s4u_account: str,
        s4u_password: str,
        service: str = "browser",
        timeout: int = 300,
    ) -> KerberosServiceTicketResult:
        """Create a forwardable ticket for a user using Impacket getST.py (S4U).

        This is a lower-level helper that encapsulates the ``getST.py`` invocation
        used by delegation exploitation flows (e.g. RBCD + S4Proxy). It assumes
        that a suitable TGT is already present in ``KRB5CCNAME``.

        Args:
            impacket_scripts_dir: Directory containing Impacket scripts (getST.py).
            domain: Target domain name.
            pdc_hostname: Hostname of the primary domain controller.
            pdc_ip: IP address of the primary domain controller.
            target_user: Privileged account to impersonate.
            s4u_account: Account (user or computer) used for S4U.
            s4u_password: Password for ``s4u_account``.
            service: Service part of the SPN (default: ``\"browser\"``).
            timeout: Maximum execution time in seconds.

        Returns:
            KerberosServiceTicketResult describing the outcome.
        """
        spn = f"{service}/{pdc_hostname}.{domain}"
        get_st_path = Path(impacket_scripts_dir).expanduser().resolve() / "getST.py"

        command_list: list[str] = []

        if not get_st_path.exists() or not os.access(get_st_path, os.X_OK):
            msg = (
                f"getST.py not found or not executable in {impacket_scripts_dir}. "
                "Please check Impacket installation."
            )
            self.logger.warning(msg)
            return KerberosServiceTicketResult(
                target_user=target_user,
                spn=spn,
                success=False,
                error_message=msg,
                command=None,
            )

        env = get_clean_env_for_compilation()
        # Preserve Kerberos-related variables such as KRB5CCNAME / KRB5_CONFIG.

        command_list = [
            str(get_st_path),
            "-spn",
            spn,
            "-impersonate",
            target_user,
            "-dc-ip",
            pdc_ip,
            f"{domain}/{s4u_account}:{s4u_password}",
        ]
        command_str = shlex.join(command_list)

        self.logger.info(
            "Creating forwardable ticket via getST.py",
            extra={"target_user": target_user, "spn": spn},
        )

        try:
            completed = self._run_command_logged(
                label="getST.py",
                command=command_list,
                timeout=timeout,
                env=env,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            msg = f"getST.py timed out after {timeout} seconds: {exc}"
            self.logger.warning(msg)
            return KerberosServiceTicketResult(
                target_user=target_user,
                spn=spn,
                success=False,
                error_message=msg,
                command=command_str,
            )
        except Exception as exc:  # pragma: no cover - defensive
            msg = f"Unexpected error running getST.py: {exc}"
            self.logger.exception(msg, exc_info=True)
            return KerberosServiceTicketResult(
                target_user=target_user,
                spn=spn,
                success=False,
                error_message=msg,
                command=command_str,
            )

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            msg = (
                stderr or f"getST.py exited with non-zero status {completed.returncode}"
            )
            self.logger.warning(
                "getST.py failed for forwardable ticket",
                extra={
                    "returncode": completed.returncode,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                },
            )
            return KerberosServiceTicketResult(
                target_user=target_user,
                spn=spn,
                success=False,
                error_message=msg,
                command=command_str,
            )

        output_text = f"{completed.stdout or ''}\n{completed.stderr or ''}".strip()
        ticket_match = re.search(r"Saving ticket in (\S+)", output_text)
        ticket_path = ticket_match.group(1) if ticket_match else None
        lowered_output = output_text.lower()
        if (
            "kdc_err_" in lowered_output
            or "kerberos sessionerror" in lowered_output
            or "doesn't exist" in lowered_output
            or not ticket_path
        ):
            msg = output_text or "getST.py did not report a saved ticket path"
            self.logger.warning(
                "getST.py returned an unusable result for %s@%s: %s",
                target_user,
                spn,
                msg,
            )
            return KerberosServiceTicketResult(
                target_user=target_user,
                spn=spn,
                success=False,
                error_message=msg,
                command=command_str,
                ticket_path=ticket_path,
            )

        self.logger.info(
            "Forwardable ticket created successfully via getST.py",
            extra={"target_user": target_user, "spn": spn},
        )
        return KerberosServiceTicketResult(
            target_user=target_user,
            spn=spn,
            success=True,
            command=command_str,
            ticket_path=ticket_path,
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


__all__ = [
    "KerberosTicketService",
    "KerberosTGTResult",
    "KerberosServiceTicketResult",
]
