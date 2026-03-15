"""CLI orchestration for hash cracking (hashcat and weakpass).

This module keeps hash cracking *UI + reporting* logic out of the monolith. The
service layer (e.g. ``HashcatCrackingService``) handles post-processing of
results; this module:

- selecciona y resuelve rutas de wordlists
- construye comandos hashcat compatibles con distintos runtimes
- maneja cracking de hashes NTLM con weakpass
- imprime cabeceras de operación y mensajes Rich
- emite telemetría de alto nivel
"""

from __future__ import annotations

from typing import Any, Protocol
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_success_verbose,
    print_warning,
    print_warning_debug,
    print_operation_header,
    telemetry,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.cli.host_file_picker import (
    is_full_container_runtime as _shared_is_full_container_runtime,
    maybe_import_host_file_to_workspace as _shared_import_host_file_to_workspace,
    select_host_file_via_gui as _shared_select_host_file_via_gui,
)
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.questionary_prompts import prompt_questionary_select
from adscan_internal.rich_output import mark_sensitive, print_exception, print_panel
from adscan_internal.text_utils import strip_ansi_codes

# Import services directly to avoid circular dependencies
try:
    from adscan_internal.services.credential_service import CredentialService
    from adscan_internal.services.kerberos_ticket_service import KerberosTicketService
except ImportError:
    # Fallback if services module has issues
    CredentialService = None  # type: ignore[assignment, misc]
    KerberosTicketService = None  # type: ignore[assignment, misc]

from adscan_internal.services.hashcat_service import HashcatCrackingService
from adscan_internal.services.cracking_history_service import (
    build_cracking_attempt,
    find_matching_attempt,
    register_cracking_attempt,
)
import rich.box
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from adscan_internal.interaction import is_non_interactive


class CrackingShell(Protocol):
    """Minimal shell surface used by the cracking controller."""

    console: object
    auto: bool
    type: str | None
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    username: str | None

    def run_command(
        self,
        command: str,
        *,
        timeout: int | None = None,
        shell: bool = False,
        capture_output: bool = False,
        text: bool = False,
        use_clean_env: bool | None = None,
        **kwargs,
    ): ...

    def _get_lab_slug(self) -> str | None: ...

    def ask_for_cracking(
        self, hash_type: str, domain: str, hashes_file: str
    ) -> None: ...

    def add_credential(
        self, domain: str, username: str, password: str, **kwargs: object
    ) -> None: ...

    def cracking(
        self, type: str, domain: str, hash: str, failed: bool = False
    ) -> None: ...

    def ask_for_kerberoast_preauth(self, domain: str, user: str) -> None: ...

    def _is_full_adscan_container_runtime(self) -> bool: ...

    def _sudo_validate(self) -> bool: ...

    def _is_ntp_service_available(self, host: str, timeout: int = 3) -> bool: ...

    def _is_tcp_port_open(self, host: str, port: int, timeout: int = 3) -> bool: ...

    def _sync_clock_via_net_time(
        self, host: str, *, domain: str | None = None
    ) -> bool: ...


class HashCrackingShell(Protocol):
    """Minimal shell surface required for weakpass hash cracking."""

    weakpass_path: str | None
    domains_data: dict

    def run_command(
        self, command: str, *, timeout: int | None = None, **kwargs
    ) -> subprocess.CompletedProcess[str] | None: ...


def choose_cracking_wordlist(
    shell: CrackingShell, hash_type: str, wordlists_dir: str
) -> str:
    """Interactive wordlist selector for cracking operations."""
    from adscan_internal import print_instruction

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    default_wordlist = (
        os.path.join(wordlists_dir, "hashmob.net_2025.medium.found")
        if workspace_type == "audit"
        else os.path.join(wordlists_dir, "rockyou.txt")
    )

    option_rows: list[tuple[str, str]]
    if workspace_type == "audit":
        option_rows = [
            (
                "hashmob_medium",
                "hashmob.net_2025.medium.found (Recommended for real world environments)",
            ),
            (
                "kaonashi14M",
                "kaonashi14M.txt (Recommended for ES environments)",
            ),
            ("rockyou", "rockyou.txt (Recommended for CTFs)"),
            ("kerberoast_pws", "kerberoast_pws (Specialized for Kerberoasting)"),
            ("other", "Other (custom path)"),
        ]
    else:
        option_rows = [
            ("rockyou", "rockyou.txt (Recommended for CTF)"),
            ("kerberoast_pws", "kerberoast_pws (AD service accounts)"),
            ("hashmob_medium", "hashmob.net_2025.medium.found"),
            ("kaonashi14M", "kaonashi14M.txt"),
            ("other", "Other (custom path)"),
        ]
    options = [label for _, label in option_rows]
    key_by_label = {label: key for key, label in option_rows}
    recommended_key = option_rows[0][0] if option_rows else "rockyou"

    message_lines = [f"Select the cracking wordlist for {hash_type}:"]
    for idx, (key, label) in enumerate(option_rows, start=1):
        suffix = " [recommended]" if key == recommended_key else ""
        message_lines.append(f"{idx}) {label}{suffix}")
    print_instruction("\n".join(message_lines) + "\n")

    if bool(getattr(shell, "auto", False)) or is_non_interactive(shell=shell):
        print_info_debug(
            "[cracking] Non-interactive/auto mode detected; using default wordlist: "
            f"{os.path.basename(default_wordlist)}."
        )
        return default_wordlist

    selection: str | None = None

    if hasattr(shell, "_questionary_select"):
        idx = shell._questionary_select(
            f"Select the cracking wordlist for {hash_type}", options, default_idx=0
        )
        if idx is None:
            selection = None
        elif 0 <= idx < len(option_rows):
            selection = option_rows[idx][0]
        else:
            selection = None
    else:
        selected_label = prompt_questionary_select(
            title=f"Select the cracking wordlist for {hash_type}",
            options=options,
        )
        selection = key_by_label.get(selected_label or "")
        if not selection:
            # Backward-compatible aliases for older wrappers/tests.
            selected_lower = str(selected_label or "").strip().lower()
            aliases = {
                "rockyou": "rockyou",
                "rockyou (default)": "rockyou",
                "kerberoast_pwd": "kerberoast_pws",
                "kerberoast_pws": "kerberoast_pws",
                "other (custom path)": "other",
                "other": "other",
                "hashmob": "hashmob_medium",
                "hashmob medium": "hashmob_medium",
                "kaonashi": "kaonashi14M",
                "kaonashi14m": "kaonashi14M",
                "kaonashi14m.txt (recommended for audit - es environments)": "kaonashi14M",
            }
            selection = aliases.get(selected_lower)
    if selection is None:
        # User aborted (Ctrl+C). Stay robust and keep workspace-aware default.
        return default_wordlist

    if selection == "rockyou":
        return os.path.join(wordlists_dir, "rockyou.txt")
    if selection == "kerberoast_pws":
        return os.path.join(wordlists_dir, "kerberoast_pws")
    if selection == "hashmob_medium":
        return os.path.join(wordlists_dir, "hashmob.net_2025.medium.found")
    if selection == "kaonashi14M":
        return os.path.join(wordlists_dir, "kaonashi14M.txt")
    if selection == "other":
        in_container_runtime = _is_full_container_runtime(shell)

        custom_path = ""
        if in_container_runtime:
            custom_path = (
                _select_host_file_via_gui(
                    shell,
                    title="Select the cracking wordlist (host file)",
                    initial_dir=str(Path.home()),
                )
                or ""
            ).strip()
            if not custom_path:
                print_info_debug(
                    "[cracking] Host GUI picker not used/failed; falling back to manual path prompt"
                )
        else:
            print_info_debug(
                "[cracking] Not running in container runtime; skipping host GUI picker"
            )

        if not custom_path:
            try:
                custom_path = (
                    Prompt.ask("Enter the full path of the wordlist", default="") or ""
                ).strip()
            except EOFError:
                print_warning(
                    "Input stream ended while requesting custom wordlist path. "
                    "Using recommended default wordlist."
                )
                return default_wordlist
        if not custom_path:
            print_warning("No path provided. Using recommended default wordlist.")
            return default_wordlist
        # In Docker runtime, user-provided paths commonly refer to the host FS and
        # will be imported into the workspace later. Avoid emitting a false warning
        # before we get a chance to do that.
        if not in_container_runtime and not os.path.exists(custom_path):
            marked_path = mark_sensitive(custom_path, "path")
            print_warning(f"Wordlist not found at {marked_path}. Hashcat may fail.")
        return custom_path

    return default_wordlist


def _is_full_container_runtime(shell: CrackingShell) -> bool:
    """Return True if running inside the ADscan FULL container runtime."""
    return _shared_is_full_container_runtime(shell)


def _select_host_file_via_gui(
    shell: CrackingShell,
    *,
    title: str,
    initial_dir: str | None = None,
) -> str | None:
    """Open a host GUI file picker (Docker runtime) and return selected host path."""
    return _shared_select_host_file_via_gui(
        shell,
        title=title,
        initial_dir=initial_dir,
        log_prefix="cracking",
    )


def _read_int_env(name: str, *, default: int) -> int:
    """Parse an int env var, returning default on errors."""

    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _maybe_import_wordlist_from_host(
    shell: CrackingShell, *, domain: str, wordlist_path: str
) -> str:
    """Best-effort: import a host file into the workspace when running in Docker.

    This is intended for Docker mode where users may type a host filesystem path
    that is not bind-mounted into the container.

    Note:
        This is intentionally permissive for now (user can paste any host path).
        If the file isn't available inside the container but the host helper is,
        we import it into the current workspace and use that path for hashcat.
    """

    return _shared_import_host_file_to_workspace(
        shell,
        domain=domain,
        source_path=wordlist_path,
        dest_dir="wordlists_custom",
        log_prefix="cracking",
    )


def _hashcat_device_args(shell: CrackingShell) -> list[str]:
    """Return hashcat device selection args (best-effort).

    In Docker, GPU passthrough may not be configured for many users. We prefer a
    robust default that works everywhere: use CPU OpenCL when no GPU devices
    are detected. If a GPU is present, let hashcat pick it by default.
    """

    cached = getattr(shell, "_hashcat_device_args_cache", None)
    if isinstance(cached, list):
        return cached

    force_cpu = os.getenv("ADSCAN_HASHCAT_FORCE_CPU", "").strip() in {
        "1",
        "true",
        "yes",
    }
    if force_cpu:
        args = ["-D", "1", "--opencl-device-types", "1"]
        setattr(shell, "_hashcat_device_args_cache", args)
        return args

    from adscan_internal.cli.tools_env import maybe_wrap_hashcat_for_container

    try:
        probe_cmd = maybe_wrap_hashcat_for_container("hashcat -I")
        probe = shell.run_command(probe_cmd, timeout=30)
        if probe is None:
            raise RuntimeError("hashcat -I probe returned no result")
        output = (
            (getattr(probe, "stdout", "") or "")
            + "\n"
            + (getattr(probe, "stderr", "") or "")
        )
        if re.search(r"Type\s*\.+?:\s*(GPU|Accelerator)\b", output, re.IGNORECASE):
            args = []
        else:
            args = ["-D", "1", "--opencl-device-types", "1"]
    except Exception:  # noqa: BLE001
        args = ["-D", "1", "--opencl-device-types", "1"]

    setattr(shell, "_hashcat_device_args_cache", args)
    return args


def _build_hashcat_cmd(
    hash_value: str, wordlist: str, mode: str, shell: CrackingShell
) -> str:
    """Build a hashcat command string for a given mode."""

    device_args = _hashcat_device_args(shell)
    tuning_args = ["-w", "1"] if device_args else []
    argv: list[str] = [
        "hashcat",
        "-m",
        mode,
        "-a",
        "0",
        "--username",
        "--force",
        *tuning_args,
        *device_args,
        hash_value,
        wordlist,
    ]
    return " ".join(shlex.quote(a) for a in argv)


def _extract_hash_users(hash_file: str) -> list[str]:
    """Extract usernames from a hash file formatted as user:hash."""
    if not os.path.exists(hash_file):
        return []
    try:
        with open(hash_file, "r", encoding="utf-8") as handle:
            users = []
            for line in handle:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                user = line.split(":", 1)[0].strip()
                if user:
                    users.append(user)
            return users
    except OSError:
        return []


def run_cracking(
    shell: CrackingShell,
    *,
    hash_type: str,
    domain: str,
    hash_file: str,
    wordlists_dir: str,
    failed: bool = False,
) -> None:
    """High-level cracking entrypoint used by the CLI shell."""
    wordlist = resolve_cracking_wordlist(
        shell=shell,
        hash_type=hash_type,
        domain=domain,
        wordlists_dir=wordlists_dir,
        failed=failed,
    )

    wordlist_name = os.path.basename(wordlist) if wordlist else "N/A"

    hash_details = {
        "asreproast": ("18200", "Kerberos 5 AS-REP etype 23"),
        "kerberoast": ("13100", "Kerberos 5 TGS-REP etype 23"),
    }
    if "NTLMv2" in hash_type:
        hashcat_mode = "5600"
        hash_description = "NetNTLMv2"
    else:
        hashcat_mode, hash_description = hash_details.get(
            hash_type,
            ("Unknown", hash_type),
        )

    print_operation_header(
        "Hash Cracking Operation",
        details={
            "Domain": domain,
            "Hash Type": hash_description,
            "Hashcat Mode": hashcat_mode,
            "Wordlist": wordlist_name,
            "Retry Attempt": "Yes" if failed else "No",
            "Hash File": hash_file,
        },
        icon="🔨",
    )

    command = None
    if hash_type == "asreproast":
        command = _build_hashcat_cmd(hash_file, wordlist, "18200", shell)
    elif hash_type == "kerberoast":
        command = _build_hashcat_cmd(hash_file, wordlist, "13100", shell)
    elif "NTLMv2" in hash_type:
        command = _build_hashcat_cmd(hash_file, wordlist, "5600", shell)

    print_warning(
        f"Cracking {hash_type} hashes. Please be patient (this may take a while)"
    )
    if command:
        marked_command = command
        try:
            marked_hash = mark_sensitive(hash_file, "path")
            marked_wordlist = mark_sensitive(wordlist, "path")
            marked_command = marked_command.replace(hash_file, marked_hash).replace(
                wordlist,
                marked_wordlist,
            )
        except Exception:  # noqa: BLE001
            pass
        print_warning_debug(f"Command: {marked_command}")

    wordlist_name_for_telemetry = os.path.basename(wordlist) if wordlist else None

    attempt_template = build_cracking_attempt(
        tool="hashcat",
        crack_type=hash_type,
        wordlist_name=wordlist_name_for_telemetry,
        wordlist_path=wordlist,
        hash_file=hash_file,
        result="started",
        cracked_count=0,
    )
    previous_attempt = find_matching_attempt(
        shell,
        domain=domain,
        attempt=attempt_template,
    )
    if previous_attempt:
        marked_domain = mark_sensitive(domain, "domain")
        marked_wordlist = mark_sensitive(
            wordlist_name_for_telemetry or wordlist or "N/A", "path"
        )
        print_warning(
            f"This cracking attempt appears to have already been run for {marked_domain} using {marked_wordlist}."
        )
        print_info_debug(
            "[cracking] repeated attempt detected: "
            f"type={hash_type} wordlist={marked_wordlist} previous_result={previous_attempt.get('result')} "
            f"previous_timestamp={previous_attempt.get('timestamp')}"
        )
        if not (getattr(shell, "auto", False) or is_non_interactive(shell=shell)):
            if not Confirm.ask(
                "Do you want to continue with this cracking attempt?",
                default=False,
            ):
                print_info(
                    "Cracking cancelled because the same inputs were already attempted."
                )
                return

    try:
        properties = {
            "hash_type": hash_type,
            "scan_mode": getattr(shell, "scan_mode", None),
            "retry": failed,
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
            "wordlist": wordlist_name_for_telemetry,
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("cracking_started", properties)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    if hash_type in {"asreproast", "kerberoast"}:
        try:
            from adscan_internal.services.attack_graph_service import (
                update_roast_entry_edge_status,
            )

            users = _extract_hash_users(hash_file)
            for user in users:
                update_roast_entry_edge_status(
                    shell,
                    domain,
                    roast_type=hash_type,
                    status="attempted",
                    username=user,
                    wordlist=wordlist_name_for_telemetry,
                )
        except Exception as exc:  # pragma: no cover
            telemetry.capture_exception(exc)

    if command:
        from adscan_internal.cli.tools_env import maybe_wrap_hashcat_for_container

        cracking_cmd = maybe_wrap_hashcat_for_container(command)
        completed_process_initial = shell.run_command(cracking_cmd, timeout=300)
        if completed_process_initial is None:
            print_error("Cracking command failed to execute.")
            register_cracking_attempt(
                shell,
                domain=domain,
                attempt=build_cracking_attempt(
                    tool="hashcat",
                    crack_type=hash_type,
                    wordlist_name=wordlist_name_for_telemetry,
                    wordlist_path=wordlist,
                    hash_file=hash_file,
                    result="error",
                    cracked_count=0,
                ),
            )
            return
        if getattr(completed_process_initial, "returncode", 0) != 0:
            combined_output = (
                (getattr(completed_process_initial, "stdout", "") or "")
                + "\n"
                + (getattr(completed_process_initial, "stderr", "") or "")
            )
            print_warning(
                "Initial cracking command may have failed. "
                f"Return code: {getattr(completed_process_initial, 'returncode', 'N/A')}",
            )
            if getattr(completed_process_initial, "stderr", None):
                print_error(
                    f"Error output: {getattr(completed_process_initial, 'stderr', '')}"
                )
            if "No devices found/left" in combined_output:
                print_warning(
                    "hashcat could not find a usable compute device (OpenCL backend). "
                    "This can happen in containers/VMs with limited OpenCL support or "
                    "memory.",
                )

    result = execute_cracking(
        shell,
        command="",
        hash_type=hash_type,
        domain=domain,
        hash=hash_file,
        wordlist_name=wordlist_name_for_telemetry,
    )
    register_cracking_attempt(
        shell,
        domain=domain,
        attempt=build_cracking_attempt(
            tool="hashcat",
            crack_type=hash_type,
            wordlist_name=wordlist_name_for_telemetry,
            wordlist_path=wordlist,
            hash_file=hash_file,
            result=str((result or {}).get("status") or "unknown"),
            cracked_count=int((result or {}).get("cracked_count") or 0),
        ),
    )


def resolve_cracking_wordlist(
    *,
    shell: CrackingShell,
    hash_type: str,
    domain: str,
    wordlists_dir: str,
    failed: bool = False,
) -> str:
    """Resolve the effective cracking wordlist using workspace-aware UX rules."""
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    should_prompt_wordlist_selector = failed or workspace_type == "audit"

    if should_prompt_wordlist_selector:
        if workspace_type == "audit" and not failed:
            print_info(
                "Audit workspace detected: select a cracking wordlist (rockyou is not forced by default)."
            )
        wordlist = choose_cracking_wordlist(shell, hash_type, wordlists_dir)
    else:
        print_info("Using rockyou as the default wordlist.")
        wordlist = os.path.join(wordlists_dir, "rockyou.txt")

    wordlist = _maybe_import_wordlist_from_host(
        shell,
        domain=domain,
        wordlist_path=wordlist,
    )
    if wordlist and not os.path.exists(wordlist):
        marked_wordlist = mark_sensitive(wordlist, "path")
        print_warning(
            f"Wordlist not found at {marked_wordlist}. Hashcat may fail; continuing anyway."
        )
    return wordlist


def ask_for_cracking(
    shell: CrackingShell,
    hash_type: str,
    domain: str,
    hashes_file: str,
    *,
    confirm: bool = True,
) -> None:
    """Ask the user whether to attempt cracking, honoring auto mode."""

    from rich.prompt import Confirm

    if shell.auto or not confirm:
        run_cracking(
            shell,
            hash_type=hash_type,
            domain=domain,
            hash_file=hashes_file,
            wordlists_dir=str(get_adscan_home() / "wordlists"),
            failed=False,
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    if Confirm.ask(
        f"Do you want to attempt to crack the {hash_type} hashes for domain {marked_domain}?",
        default=True,
    ):
        run_cracking(
            shell,
            hash_type=hash_type,
            domain=domain,
            hash_file=hashes_file,
            wordlists_dir=str(get_adscan_home() / "wordlists"),
            failed=False,
        )


def run_sync_clock(shell: CrackingShell, domain: str, *, verbose: bool = False) -> bool:
    """Synchronize local system clock with PDC using the service layer.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name for clock synchronization.
        verbose: Whether to emit verbose messages.

    Returns:
        True if clock synchronization succeeded, False otherwise.
    """
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain '{marked_domain}' is not configured.")
        return False

    pdc_ip = shell.domains_data[domain].get("pdc")
    if not pdc_ip:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"PDC not configured for domain '{marked_domain}'.")
        return False

    marked_domain = mark_sensitive(domain, "domain")
    marked_pdc = mark_sensitive(pdc_ip, "ip")
    print_operation_header(
        "Clock Synchronization",
        details={
            "Domain": domain,
            "PDC": pdc_ip,
            "Method": "NTP / RPC",
        },
        icon="🕐",
    )

    service = KerberosTicketService()
    success = service.sync_clock_with_pdc(
        pdc_ip=pdc_ip,
        domain=domain,
        is_full_container_runtime=shell._is_full_adscan_container_runtime,
        sudo_validate=shell._sudo_validate,
        is_ntp_service_available=shell._is_ntp_service_available,
        is_tcp_port_open=shell._is_tcp_port_open,
        run_command=shell.run_command,
        sync_clock_via_net_time=shell._sync_clock_via_net_time,
        scan_id=None,
        verbose=verbose,
    )

    if success:
        print_success_verbose(f"Clock synchronized successfully with PDC {marked_pdc}")
    else:
        print_warning(f"Failed to synchronize clock with PDC {marked_pdc}")

    return success


def run_password_spraying(
    shell: CrackingShell,
    command: str,
    domain: str,
) -> None:
    """Execute password spraying command using the service layer.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name for spraying operation.
        command: Full kerbrute command string to execute.
    """
    from adscan_internal.cli.common import SECRET_MODE

    marked_domain = mark_sensitive(domain, "domain")
    print_warning(
        f"Performing the spraying on {marked_domain}. Please be patient (this can take a while)"
    )

    # Create executor that uses shell.run_command
    def executor(cmd: str, timeout: int | None) -> Any:
        from adscan_internal.subprocess_env import command_string_needs_clean_env

        use_clean_env = command_string_needs_clean_env(cmd)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[spray] Executing spraying command with "
            f"use_clean_env={use_clean_env} on domain {marked_domain}"
        )

        return shell.run_command(
            cmd,
            timeout=timeout,
            shell=True,
            capture_output=True,
            text=True,
            use_clean_env=use_clean_env,
        )

    service = CredentialService()
    result = service.execute_password_spraying(
        command=command,
        domain=domain,
        executor=executor,
        scan_id=None,
    )

    # Process results and display to user
    if result["returncode"] != 0:
        print_error(
            f"Password spraying command failed with return code: {result['returncode']}"
        )
        print_warning_debug(
            f"[spray] Debug context: returncode={result['returncode']}, "
            f"stdout_len={len(result['stdout'])}, stderr_len={len(result['stderr'])}"
        )

        output_lines = result["stdout"].splitlines() if result["stdout"] else []
        if output_lines:
            print_warning("Command output (last 20 lines):")
            for line in output_lines[-20:]:
                print_info_verbose(f"  {line}")

        if result["stderr"]:
            print_warning_debug("[spray] Error output:")
            for line in result["stderr"].splitlines():
                clean_line = strip_ansi_codes(line)
                print_info_debug(f"[spray][stderr] {clean_line}")
    elif not result["found_credentials"]:
        print_warning("No valid credentials found.")
        if result["stdout"] and SECRET_MODE:
            print_info_verbose("Full command output:")
            for line in result["stdout"].splitlines():
                print_info_verbose(f"  {line}")
        elif result["stdout"]:
            error_lines = [
                line
                for line in result["stdout"].splitlines()
                if "error" in line.lower() or "failed" in line.lower()
            ]
            if error_lines:
                print_warning("Errors detected in output:")
                for line in error_lines[:5]:
                    print_info_verbose(f"  {line}")

    # Process found credentials
    for cred in result["credentials"]:
        username = cred["username"]
        password = cred["password"]
        print_success(f"[!] VALID LOGIN: {username}@{domain}:{password}")
        shell.add_credential(domain, username, password)


def handle_hash_cracking(
    shell: HashCrackingShell, domain: str, user: str, cred: str
) -> tuple[str, bool]:
    """Attempt to crack an NTLM hash with weakpass.

    Args:
        shell: Shell instance with weakpass_path, license_mode, and helper methods.
        domain: Domain name for the credential.
        user: Username for the credential.
        cred: NTLM hash to crack.

    Returns:
        Tuple of (credential, is_hash). If cracking succeeds, returns the
        cracked password and False. On failure, returns original hash
        and True.
    """
    try:
        marked_cred = mark_sensitive(cred, "password")
        command = f"{shell.weakpass_path} -H {marked_cred}"
        marked_user = mark_sensitive(user, "user")
        print_info_verbose(f"Attempting to crack NTLM hash for user '{marked_user}'...")
        print_info_debug(f"Command: {command}")
        proc = shell.run_command(command)

        if (
            isinstance(proc, subprocess.CompletedProcess)
            and proc.returncode == 0
            and proc.stdout
            and "Cracked hash" in proc.stdout
        ):
            password = proc.stdout.split(":")[-1].strip()
            marked_user = mark_sensitive(user, "user")
            marked_password = mark_sensitive(password, "password")
            print_warning(
                f"Hash cracked successfully for user '{marked_user}'. Password cracked: {marked_password}"
            )
            return password, False

        if isinstance(proc, subprocess.CompletedProcess):
            marked_user = mark_sensitive(user, "user")
            print_info_verbose(
                f"Could not crack the hash for user '{marked_user}'. Proceeding with the hash."
            )
    except Exception as e:  # pragma: no cover - mirrors legacy best-effort handling
        telemetry.capture_exception(e)
        print_error("An unexpected error occurred during hash cracking.")
        print_exception(show_locals=False, exception=e)

    return cred, True  # Return original hash if cracking fails


def handle_hash_cracking_batch(
    shell: HashCrackingShell, hashes: list[str]
) -> dict[str, str]:
    """Attempt to crack multiple NTLM hashes with a single weakpass call.

    Args:
        shell: Shell instance with weakpass_path and run_command.
        hashes: Candidate NTLM hashes (32 hex chars). Duplicates are allowed.

    Returns:
        Mapping ``hash_lower -> cracked_password`` for successfully cracked
        hashes. Missing entries indicate "not cracked".
    """
    if not hashes:
        return {}
    if not getattr(shell, "weakpass_path", None):
        return {}

    valid_hashes: list[str] = []
    seen_hashes: set[str] = set()
    for hash_value in hashes:
        candidate = str(hash_value or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", candidate):
            continue
        if candidate in seen_hashes:
            continue
        seen_hashes.add(candidate)
        valid_hashes.append(candidate)

    if not valid_hashes:
        return {}

    temp_file_path = ""
    cracked_by_hash: dict[str, str] = {}
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            prefix="adscan-weakpass-",
            suffix=".txt",
        ) as temp_file:
            temp_file.write("\n".join(valid_hashes))
            temp_file.write("\n")
            temp_file_path = temp_file.name

        command = (
            f"{shell.weakpass_path} -f {shlex.quote(temp_file_path)} "
            f"-w {max(4, min(32, len(valid_hashes)))}"
        )
        masked_temp_file = mark_sensitive(temp_file_path, "path")
        command_for_log = (
            f"{shell.weakpass_path} -f {masked_temp_file} "
            f"-w {max(4, min(32, len(valid_hashes)))}"
        )
        print_info_verbose(
            f"Attempting batch NTLM crack for {len(valid_hashes)} hash(es)..."
        )
        print_info_debug(f"Command: {command_for_log}")
        proc = shell.run_command(command)
        stdout = proc.stdout if isinstance(proc, subprocess.CompletedProcess) else ""

        for raw_line in str(stdout or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = re.search(
                r"Cracked hash:\s*([0-9a-fA-F]{32})\s*:(.*)$",
                line,
            )
            if not match:
                continue
            hash_key = match.group(1).lower()
            password = match.group(2).strip()
            if password:
                cracked_by_hash[hash_key] = password

        # weakpass bulk mode usually writes cracked pairs to `<input>_cracked.txt`.
        # Parse that file when stdout only contains summary lines.
        cracked_output_file = f"{os.path.splitext(temp_file_path)[0]}_cracked.txt"
        if os.path.exists(cracked_output_file):
            try:
                with open(cracked_output_file, "r", encoding="utf-8") as output_handle:
                    for raw_line in output_handle:
                        line = raw_line.strip()
                        if not line or ":" not in line:
                            continue
                        hash_value, password = line.split(":", 1)
                        hash_key = hash_value.strip().lower()
                        plain_value = password.strip()
                        if re.fullmatch(r"[0-9a-f]{32}", hash_key) and plain_value:
                            cracked_by_hash[hash_key] = plain_value
            except Exception as file_exc:  # pragma: no cover - best effort only
                telemetry.capture_exception(file_exc)
                print_warning_debug(
                    "Failed to parse weakpass cracked output file; "
                    "continuing with stdout-derived results."
                )

        print_info_verbose(
            f"Batch NTLM crack finished: {len(cracked_by_hash)}/{len(valid_hashes)} hash(es) cracked."
        )
    except Exception as e:  # pragma: no cover - mirrors existing best-effort handling
        telemetry.capture_exception(e)
        print_error("An unexpected error occurred during batch hash cracking.")
        print_exception(show_locals=False, exception=e)
    finally:
        if temp_file_path:
            try:
                os.unlink(temp_file_path)
            except OSError:
                pass
            cracked_output_file = f"{os.path.splitext(temp_file_path)[0]}_cracked.txt"
            uncracked_output_file = (
                f"{os.path.splitext(temp_file_path)[0]}_uncracked.txt"
            )
            for auxiliary_file in (cracked_output_file, uncracked_output_file):
                try:
                    if os.path.exists(auxiliary_file):
                        os.unlink(auxiliary_file)
                except OSError:
                    pass

    return cracked_by_hash


def do_cracking(shell: CrackingShell, args: str) -> None:
    """
    Command to crack Active Directory hashes.

    Usage: cracking <type> <domain> <hash>

    Where:
    - <type> is the type of hash to crack (asreproast, kerberoast, NTLMv2)
    - <domain> is the Active Directory domain of the hash
    - <hash> is the hash to crack

    This command uses hashcat to crack the hash with the wordlist selected by the user.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: cracking <type> <domain> <hash>")
        return
    hash_type = args_list[0]
    domain = args_list[1]
    hash_file = args_list[2]
    shell.cracking(hash_type, domain, hash_file)


def run_cracking_history(
    shell: CrackingShell,
    *,
    domain: str,
    recent_limit: int = 20,
) -> None:
    """Render recent cracking attempts stored in workspace history."""
    from adscan_internal.services.cracking_history_service import get_cracking_history

    history = get_cracking_history(shell)
    domain_entry = history.get(domain, {}) if isinstance(history, dict) else {}
    attempts = domain_entry.get("attempts", []) if isinstance(domain_entry, dict) else []
    if not isinstance(attempts, list) or not attempts:
        marked_domain = mark_sensitive(domain, "domain")
        print_panel(
            f"[yellow]No cracking history found for {marked_domain}.[/yellow]",
            title="Cracking History",
            border_style="yellow",
        )
        return

    limited_attempts = attempts[-max(1, int(recent_limit)) :]
    table = Table(
        title="Cracking History",
        show_header=True,
        header_style="bold magenta",
        box=rich.box.ROUNDED,
    )
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Tool", style="cyan")
    table.add_column("Type", style="bold")
    table.add_column("Wordlist", style="white", overflow="fold")
    table.add_column("Result", style="bold")
    table.add_column("Cracked", style="green", justify="right")
    table.add_column("Targets", style="white", overflow="fold")
    table.add_column("When", style="dim")

    for idx, attempt in enumerate(reversed(limited_attempts), start=1):
        if not isinstance(attempt, dict):
            continue
        target_users = attempt.get("target_users") or []
        artifact_paths = attempt.get("artifact_paths") or []
        targets = ", ".join(str(user) for user in target_users[:3] if str(user).strip())
        if not targets and artifact_paths:
            targets = ", ".join(str(path) for path in artifact_paths[:2] if str(path).strip())
        if len(target_users) > 3:
            targets = f"{targets}, +{len(target_users) - 3} more"
        elif not targets:
            targets = "-"

        wordlist = str(attempt.get("wordlist_name") or attempt.get("wordlist_path") or "-")
        result = str(attempt.get("result") or "unknown")
        result_style = {
            "success": "green",
            "no_match": "yellow",
            "error": "red",
        }.get(result, "white")
        table.add_row(
            str(idx),
            str(attempt.get("tool") or "-"),
            str(attempt.get("crack_type") or "-"),
            mark_sensitive(wordlist, "path"),
            f"[{result_style}]{result}[/{result_style}]",
            str(int(attempt.get("cracked_count") or 0)),
            mark_sensitive(targets, "user"),
            str(attempt.get("timestamp") or "-"),
        )

    print_operation_header(
        "Cracking History",
        details={
            "Domain": domain,
            "Entries": len(attempts),
            "Showing": min(len(attempts), max(1, int(recent_limit))),
        },
        icon="🧾",
    )
    shell.console.print(table)


def execute_cracking(
    shell: CrackingShell,
    command: str,
    hash_type: str,
    domain: str,
    hash: str,
    wordlist_name: str | None = None,
 ) -> dict[str, object]:
    """Execute the cracking command and process results."""
    from adscan_internal.cli.tools_env import maybe_wrap_hashcat_for_container
    import sys

    try:
        # First phase: execute the initial cracking command
        if command:
            cracking_cmd = maybe_wrap_hashcat_for_container(command)
            completed_process_initial = shell.run_command(cracking_cmd, timeout=300)

            if completed_process_initial is None:
                print_error("Cracking command failed to execute.")
                return {"status": "error", "cracked_count": 0}

            if completed_process_initial.returncode != 0:
                print_warning(
                    f"Initial cracking command may have failed. Return code: {completed_process_initial.returncode}"
                )
                combined_output = (
                    (completed_process_initial.stdout or "")
                    + "\n"
                    + (completed_process_initial.stderr or "")
                )
                if completed_process_initial.stderr:
                    print_error(f"Error output: {completed_process_initial.stderr}")
                if "No devices found/left" in combined_output:
                    print_warning(
                        "hashcat could not find a usable compute device (OpenCL backend). "
                        "This can happen in containers/VMs with limited OpenCL support or memory."
                    )
                    try:
                        probe_cmd = maybe_wrap_hashcat_for_container("hashcat -I")
                        probe = shell.run_command(probe_cmd, timeout=30)
                        if probe is None:
                            raise RuntimeError("hashcat -I probe returned no result")
                        probe_out = (probe.stdout or "") + "\n" + (probe.stderr or "")
                        print_info_debug(
                            "hashcat -I output (first 40 lines):\n"
                            + "\n".join(probe_out.splitlines()[:40])
                        )
                    except Exception:
                        print_info_debug(
                            "hashcat -I probe failed while diagnosing devices."
                        )

        # Second phase: hashcat --show to extract cracked passwords
        file_name = f"cracked_{hash_type}.txt"
        cracking_directory = os.path.join(
            shell.current_workspace_dir or os.getcwd(),
            "domains",
            domain,
            "cracking",
        )
        os.makedirs(cracking_directory, exist_ok=True)
        file_path = os.path.join(cracking_directory, file_name)

        show_argv = [
            "hashcat",
            "--username",
            "--outfile-format",
            "2",
            hash,
            "--show",
        ]
        show_cmd = " ".join(shlex.quote(str(a)) for a in show_argv)
        show_cmd = maybe_wrap_hashcat_for_container(show_cmd)
        print_info_debug(f"Executing hashcat show command: {show_cmd}")
        completed_process_show = shell.run_command(show_cmd, timeout=300)

        if completed_process_show is None:
            print_warning("'hashcat --show' command failed to execute.")
        elif completed_process_show.returncode != 0:
            print_warning(
                f"'hashcat --show' command may have failed. Return code: {completed_process_show.returncode}"
            )
            if completed_process_show.stderr:
                print_error(f"Error output: {completed_process_show.stderr}")

        show_stdout = ""
        if completed_process_show is not None and completed_process_show.stdout:
            show_stdout = completed_process_show.stdout.strip()
        show_lines = []
        if show_stdout:
            for line in show_stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                if ":" not in line:
                    continue
                if line.startswith("NOTE:") or line.lower().startswith("hash-mode"):
                    continue
                if line.lower().startswith("do not report"):
                    continue
                left = line.split(":", 1)[0].strip()
                if not left or " " in left:
                    continue
                show_lines.append(line)
        try:
            with open(file_path, "w", encoding="utf-8") as handle:
                for line in show_lines:
                    handle.write(line + "\n")
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_error("Failed to write hashcat cracked output file.")
            print_exception(show_locals=False, exception=exc)

        # Third phase: extract and display credentials
        if os.path.exists(file_path) and os.path.getsize(file_path) > 1:
            service = HashcatCrackingService()
            result = service.extract_creds_from_hash(file_path)
            if result and result.has_credentials():
                creds = result.credentials
                # Telemetry: track successful hash cracking
                try:
                    properties = {
                        "hash_type": hash_type,
                        "credentials_cracked": len(creds),
                        "scan_mode": getattr(shell, "scan_mode", None),
                        "workspace_type": shell.type,
                        "auto_mode": shell.auto,
                        "wordlist": wordlist_name,
                    }
                    properties.update(
                        build_lab_event_fields(shell=shell, include_slug=True)
                    )
                    telemetry.capture("hash_cracked", properties)
                    # Track victory for session summary (Hormozi: Give:Ask ratio)
                    if hasattr(shell, "_session_victories"):
                        shell._session_victories.append("hash_cracked")
                except Exception as e:
                    telemetry.capture_exception(e)
                try:
                    if str(getattr(shell, "type", "") or "").strip().lower() == "audit":
                        audit_properties = {
                            "hash_type": hash_type,
                            "wordlist": wordlist_name,
                            "hashes_cracked": len(creds),
                            "scan_mode": getattr(shell, "scan_mode", None),
                            "workspace_type": getattr(shell, "type", None),
                            "auto_mode": getattr(shell, "auto", False),
                        }
                        audit_properties.update(
                            build_lab_event_fields(shell=shell, include_slug=True)
                        )
                        telemetry.capture(
                            "audit_wordlist_cracked",
                            audit_properties,
                        )
                except Exception as exc:  # pragma: no cover - telemetry best effort
                    telemetry.capture_exception(exc)

                table = Table(
                    title="[bold green]🔓 Cracked Credentials[/bold green]",
                    show_header=True,
                    header_style="bold magenta",
                    box=rich.box.ROUNDED,
                )
                table.add_column("Username", style="cyan")
                table.add_column("Password", style="green")
                for username, password in creds.items():
                    marked_username = mark_sensitive(username, "user")
                    marked_password = mark_sensitive(password, "password")
                    table.add_row(marked_username, marked_password)
                shell.console.print(
                    Panel(table, title="Hash Cracked", border_style="green")
                )
                # Persist credentials after displaying them
                attempted_users = set(_extract_hash_users(hash))
                cracked_users = set(creds.keys())
                for username, password in creds.items():
                    if hash_type in {"asreproast", "kerberoast"}:
                        try:
                            from adscan_internal.services.attack_graph_service import (
                                update_roast_entry_edge_status,
                            )

                            update_roast_entry_edge_status(
                                shell,
                                domain,
                                roast_type=hash_type,
                                status="success",
                                username=username,
                                wordlist=wordlist_name,
                            )
                        except Exception as exc:  # pragma: no cover
                            telemetry.capture_exception(exc)
                    shell.add_credential(domain, username, password)

                # Mark remaining attempted users as failed for this wordlist.
                if hash_type in {"asreproast", "kerberoast"}:
                    remaining = sorted(
                        (attempted_users - cracked_users),
                        key=str.lower,
                    )
                    for user in remaining:
                        try:
                            from adscan_internal.services.attack_graph_service import (
                                update_roast_entry_edge_status,
                            )

                            update_roast_entry_edge_status(
                                shell,
                                domain,
                                roast_type=hash_type,
                                status="failed",
                                username=user,
                                wordlist=wordlist_name,
                            )
                        except Exception as exc:  # pragma: no cover
                            telemetry.capture_exception(exc)
                return {"status": "success", "cracked_count": len(creds)}
            else:
                print_panel(
                    "[red]No valid credentials were found in the file.[/red]",
                    border_style="red",
                )
                return {"status": "no_match", "cracked_count": 0}
        else:
            # Telemetry: track failed hash cracking
            try:
                properties = {
                    "hash_type": hash_type,
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                    "wordlist": wordlist_name,
                }
                properties.update(
                    build_lab_event_fields(shell=shell, include_slug=True)
                )
                telemetry.capture("hash_not_cracked", properties)
            except Exception as e:
                telemetry.capture_exception(e)

            print_panel("[red]Hash not cracked[/red]", border_style="red")
            if hash_type in {"asreproast", "kerberoast"}:
                try:
                    from adscan_internal.services.attack_graph_service import (
                        update_roast_entry_edge_status,
                    )

                    users = _extract_hash_users(hash)
                    for user in users:
                        update_roast_entry_edge_status(
                            shell,
                            domain,
                            roast_type=hash_type,
                            status="failed",
                            username=user,
                            wordlist=wordlist_name,
                        )
                except Exception as exc:  # pragma: no cover
                    telemetry.capture_exception(exc)
            if hash_type == "asreproast":
                marked_domain = mark_sensitive(domain, "domain")
                is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
                if (
                    sys.stdin.isatty()
                    and not is_ci
                    and Confirm.ask(
                        f"Do you want to crack the asreproast hashes for domain {marked_domain} with another wordlist?",
                        default=False,
                    )
                ):
                    shell.cracking("asreproast", domain, hash, failed=True)
            if (
                hash_type == "asreproast"
                and shell.domains_data[domain]["auth"] != "auth"
            ):
                shell.ask_for_kerberoast_preauth(domain, shell.username or "")
            if hash_type == "kerberoast":
                marked_domain = mark_sensitive(domain, "domain")
                is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
                if (
                    sys.stdin.isatty()
                    and not is_ci
                    and Confirm.ask(
                        f"Do you want to crack the kerberoast hashes for domain {marked_domain} with another wordlist?",
                        default=False,
                    )
                ):
                    shell.cracking("kerberoast", domain, hash, failed=True)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing hashcat.")
        print_exception(show_locals=False, exception=e)
        return {"status": "error", "cracked_count": 0}

    return {"status": "no_match", "cracked_count": 0}


__all__ = [
    "CrackingShell",
    "HashCrackingShell",
    "ask_for_cracking",
    "choose_cracking_wordlist",
    "run_cracking",
    "do_cracking",
    "execute_cracking",
    "run_sync_clock",
    "run_password_spraying",
    "handle_hash_cracking",
]
