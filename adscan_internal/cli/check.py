"""Helpers for legacy `adscan check`.

This module hosts small, dependency-light helpers used by `handle_check` to
keep `adscan.py` slimmer while preserving behaviour.

The functions here intentionally rely on dependency injection so we don't
introduce import cycles back into `adscan.py`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import importlib
import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
import signal
from typing import Any, Dict, List

from adscan_core.path_utils import get_adscan_state_dir
from adscan_core.version_context import get_telemetry_version_fields
from adscan_launcher.update_manager import (
    get_local_update_recency_summary,
    is_dev_update_context,
)
from rich.console import Group
from rich.text import Text
from adscan_core.linux_capabilities import (
    CAP_NET_ADMIN_BIT as _CAP_NET_ADMIN_BIT,
    CAP_NET_BIND_SERVICE_BIT as _CAP_NET_BIND_SERVICE_BIT,
    binary_has_capability,
    get_binary_capabilities,
    process_has_capability,
)
from adscan_internal.ligolo_manager import (
    LIGOLO_NG_VERSION,
    get_current_ligolo_proxy_target,
    get_ligolo_agent_local_path,
    get_ligolo_proxy_local_path,
)


_MINIMUM_HASHCAT_VERSION = (7, 1, 2)
_JOHN_AVX2_REQUIRED_RE = re.compile(r"avx2 is required for this build", re.IGNORECASE)
_RUNTIME_MANAGED_JOHN_PATHS = (
    "/opt/adscan/tools/john/run/john",
    "/opt/adscan/bin/john",
)
_REQUIRED_JOHN_CONVERTERS = (
    "keepass2john",
    "zip2john",
    "pfx2john",
    "ansible2john",
)
_RUNTIME_PYTHON_DEPENDENCIES = (
    ("netifaces", "netifaces", "required for ADscan network/runtime startup flows"),
    ("certihound", "CertiHound", "used for ADCS BloodHound collection"),
    ("gssapi", "gssapi", "required for CertiHound Kerberos authentication"),
    ("krb5", "krb5", "required for WinRM Kerberos (pyspnego backend)"),
    ("Crypto", "pycryptodome", "required for CertiHound password authentication"),
    ("pykeepass", "pykeepass", "used for KeePass artifact parsing"),
    ("impacket", "impacket", "used by SMB/DCERPC/Kerberos-backed runtime services"),
    ("markitdown", "markitdown", "used for runtime document content extraction"),
    ("pydantic_ai", "pydantic_ai", "used for ADscan AI runtime features"),
    ("pypsrp", "pypsrp", "required for WinRM/PSRP runtime operations"),
    ("graphviz", "graphviz", "used for runtime graph rendering features"),
    ("matplotlib", "matplotlib", "used for runtime chart/report rendering"),
    ("pyarrow", "pyarrow", "used for runtime materialized attack-path caches"),
    ("selenium", "selenium", "used for runtime browser-backed discovery features"),
    ("textual", "textual", "required for the ADscan TUI runtime"),
    ("magic", "python-magic", "used for runtime file type detection"),
    ("rustworkx", "rustworkx", "used for runtime attack-graph processing"),
    ("neo4j", "neo4j", "used for BloodHound/Neo4j-backed runtime integrations"),
)
_RUNTIME_PYTHON_DISTRIBUTION_NAMES = {
    "netifaces": "netifaces",
    "certihound": "certihound",
    "gssapi": "gssapi",
    "krb5": "krb5",
    "Crypto": "pycryptodome",
    "pykeepass": "pykeepass",
    "impacket": "impacket",
    "markitdown": "markitdown",
    "pydantic_ai": "pydantic-ai",
    "pypsrp": "pypsrp",
    "graphviz": "graphviz",
    "matplotlib": "matplotlib",
    "pyarrow": "pyarrow",
    "selenium": "selenium",
    "textual": "textual",
    "magic": "python-magic",
    "rustworkx": "rustworkx",
    "neo4j": "neo4j",
}


@dataclass(frozen=True)
class CheckFailureRecoveryGuidance:
    """User-facing recovery guidance for failed `adscan check` runs."""

    status_message: str
    instruction: str
    follow_up_message: str | None = None
    interactive_prompt: str | None = None


def _check_container_runtime_version_alignment(deps: Any) -> bool:
    """Return whether launcher/runtime version metadata looks aligned."""
    version_fields = get_telemetry_version_fields()
    launcher_version = str(version_fields.get("launcher_version") or "").strip()
    runtime_version = str(version_fields.get("runtime_version") or "").strip()
    launcher_source = str(version_fields.get("launcher_version_source") or "unknown")
    runtime_source = str(version_fields.get("runtime_version_source") or "unknown")

    deps.print_info_debug(
        "[check] container runtime version context: "
        f"launcher_version={launcher_version!r} ({launcher_source}), "
        f"runtime_version={runtime_version!r} ({runtime_source})"
    )

    if not launcher_version or not runtime_version or launcher_version == runtime_version:
        return True

    deps.print_warning("Launcher/runtime version mismatch detected.")
    print_panel = getattr(deps, "print_panel", None)
    if callable(print_panel):
        print_panel(
            Group(
                Text(
                    f"Launcher: {launcher_version} ({launcher_source})",
                    style="bold yellow",
                ),
                Text(
                    f"Runtime: {runtime_version} ({runtime_source})",
                    style="bold yellow",
                ),
                Text(
                    "State mismatch can cause incorrect checks, stale bug behavior, "
                    "and older attack/escalation coverage.",
                    style="cyan",
                ),
                Text("Action: Run on the host: adscan update", style="bold white"),
            ),
            title="Version Alignment",
            border_style="yellow",
            padding=(1, 2),
        )
    deps.print_info(
        "Launcher version "
        f"{launcher_version} ({launcher_source}) does not match runtime version "
        f"{runtime_version} ({runtime_source})."
    )
    deps.print_instruction("Run on the host: adscan update")
    deps.print_info(
        "Keeping both the launcher and runtime image updated is recommended because "
        "updates regularly ship bug fixes, new attack coverage, and new escalation paths."
    )
    return False


def _emit_local_update_recency_guidance(deps: Any) -> None:
    """Render local update recency guidance when the launcher/runtime looks stale."""
    if is_dev_update_context():
        deps.print_info_debug(
            "[check] Dev channel detected; skipping local update recency guidance."
        )
        return
    recency = get_local_update_recency_summary(str(get_adscan_state_dir()))
    recency_message = str(recency.get("message") or "").strip()
    if not recency_message:
        return
    deps.print_info_debug(
        "[check] local update recency: "
        f"status={recency.get('status')!r}, "
        f"has_successful_update={recency.get('has_successful_update')!r}, "
        f"is_stale={recency.get('is_stale')!r}, "
        f"age_days={recency.get('age_days')!r}, "
        f"install_initialized_at={recency.get('install_initialized_at')!r}, "
        f"message={recency_message!r}"
    )
    if recency.get("status") == "bootstrap":
        initialized_at = str(recency.get("install_initialized_at") or "").strip()
        if initialized_at:
            deps.print_info_debug(
                "[check] bootstrap install detected; "
                f"install_initialized_at={initialized_at!r}"
            )
    if not bool(recency.get("is_stale")):
        return
    deps.print_warning("Local update cadence looks stale.")
    print_panel = getattr(deps, "print_panel", None)
    if callable(print_panel):
        print_panel(
            Group(
                Text(recency_message, style="bold yellow"),
                Text(
                    "Older launcher/runtime state can leave bug fixes, new attack coverage, "
                    "and escalation improvements unapplied.",
                    style="cyan",
                ),
                Text("Action: Run on the host: adscan update", style="bold white"),
            ),
            title="Maintenance",
            border_style="yellow",
            padding=(1, 2),
        )
    deps.print_instruction("Run on the host: adscan update")


def get_check_failure_recovery_guidance(
    *, full_container_runtime: bool
) -> CheckFailureRecoveryGuidance:
    """Return the best recovery guidance for a failed check session.

    Args:
        full_container_runtime: Whether the check ran inside the ADscan Docker
            runtime rather than on the host launcher.

    Returns:
        Structured guidance for summary panels and interactive recovery prompts.
    """
    if full_container_runtime:
        return CheckFailureRecoveryGuidance(
            status_message=(
                "This check ran inside the ADscan Docker runtime. "
                "Run 'adscan update' on the host to refresh the launcher and "
                "runtime image, then rerun this command."
            ),
            instruction="Run on the host: adscan update",
        )

    return CheckFailureRecoveryGuidance(
        status_message=(
            "Some components are missing. Run 'adscan check --fix' to attempt "
            "automatic repairs."
        ),
        instruction="Try: adscan check --fix",
        interactive_prompt="Try to fix automatically now (runs `adscan check --fix`)?",
    )


def _resolve_runtime_managed_john_converter_path(converter_name: str) -> str | None:
    """Resolve one runtime-managed ``*2john`` converter path."""
    normalized_name = str(converter_name or "").strip()
    if not normalized_name:
        return None

    candidates = [
        shutil.which(normalized_name),
        shutil.which(f"{normalized_name}.py"),
        shutil.which(f"{normalized_name}.pl"),
        f"/opt/adscan/bin/{normalized_name}",
        f"/opt/adscan/bin/{normalized_name}.py",
        f"/opt/adscan/bin/{normalized_name}.pl",
        f"/opt/adscan/tools/john/run/{normalized_name}",
        f"/opt/adscan/tools/john/run/{normalized_name}.py",
        f"/opt/adscan/tools/john/run/{normalized_name}.pl",
    ]
    for candidate in candidates:
        normalized_candidate = str(candidate or "").strip()
        if normalized_candidate and os.path.exists(normalized_candidate) and os.access(
            normalized_candidate, os.X_OK
        ):
            return os.path.realpath(normalized_candidate)
    return None


def _validate_runtime_managed_john_converters(
    *,
    john_executable: str,
    deps: Any,
) -> list[str]:
    """Validate the John converters ADscan uses for artifact cracking."""
    normalized_john = str(john_executable or "").strip()
    if not normalized_john:
        return []
    if normalized_john not in _RUNTIME_MANAGED_JOHN_PATHS and not normalized_john.startswith(
        "/opt/adscan/"
    ):
        return []

    missing_converters: list[str] = []
    for converter_name in _REQUIRED_JOHN_CONVERTERS:
        converter_path = _resolve_runtime_managed_john_converter_path(converter_name)
        if converter_path:
            deps.print_info_debug(
                "[check] Found required John converter: "
                f"{converter_name} -> {converter_path}"
            )
            continue
        missing_converters.append(converter_name)

    if not missing_converters:
        deps.print_success(
            "Required John artifact converters are available "
            f"({', '.join(_REQUIRED_JOHN_CONVERTERS)})"
        )
        return []

    return [
        "John the Ripper runtime is missing required artifact converters: "
        + ", ".join(missing_converters)
        + "."
    ]


def should_offer_interactive_check_repair(
    *,
    args: Any | None,
    ci_env: str | None,
    stdin_isatty: bool,
    guidance: CheckFailureRecoveryGuidance,
) -> bool:
    """Return whether interactive repair should be offered to the user."""
    return (
        guidance.interactive_prompt is not None
        and args is not None
        and getattr(args, "command", None) == "check"
        and not ci_env
        and stdin_isatty
    )


def should_offer_failed_check_override(
    *,
    args: Any | None,
    ci_env: str | None,
    stdin_isatty: bool,
) -> bool:
    """Return whether the user should be offered a continue-anyway override."""
    return (
        args is not None
        and getattr(args, "command", None) == "check"
        and not ci_env
        and stdin_isatty
    )


@dataclass(frozen=True)
class VirtualEnvCheckConfig:
    """Configuration for checking the legacy host virtual environment."""

    adscan_base_dir: str
    venv_path: str
    full_container_runtime: bool
    fix_mode: bool


@dataclass(frozen=True)
class VirtualEnvCheckDeps:
    """Dependency bundle for virtual environment checks."""

    ensure_dir_writable: Callable[..., bool]
    install_pyenv_python_and_venv: Callable[..., tuple[bool, object, object]]
    run_command: Callable[..., object]
    path_exists: Callable[[str], bool]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    telemetry_capture_exception: Callable[[BaseException], None]
    print_exception: Callable[..., None] | None = None


def check_virtual_environment(
    *,
    config: VirtualEnvCheckConfig,
    deps: VirtualEnvCheckDeps,
) -> tuple[bool, bool]:
    """Check the ADscan host virtual environment status.

    This is the legacy host-based venv check used by `handle_check`. In the FULL
    Docker runtime, this check is skipped because tool envs are pre-provisioned.

    Args:
        config: Static configuration for the venv check.
        deps: Injected dependencies (I/O, subprocess, telemetry, printing).

    Returns:
        Tuple of:
            - adscan_venv_ok: Whether the venv is usable.
            - all_ok: Whether the overall check should remain successful so far.
    """
    all_ok = True
    venv_python = os.path.join(config.venv_path, "bin", "python")
    adscan_venv_ok = False

    if config.full_container_runtime:
        deps.print_info_verbose(
            "Running inside the ADscan FULL container - skipping host virtual environment checks."
        )
        return True, all_ok

    if deps.path_exists(venv_python):
        adscan_venv_ok = True
        try:
            # Keep the command identical to the legacy behaviour.
            version_probe = (
                "import sys; "
                "print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
            )
            result = deps.run_command(
                [venv_python, "-c", version_probe],
                capture_output=True,
                text=True,
                check=True,
            )
            python_version = getattr(result, "stdout", "").strip()

            if python_version == "3.12.3":
                deps.print_success(
                    f"Virtual environment found: {config.venv_path} (Python {python_version})"
                )
            else:
                deps.print_warning(
                    f"Virtual environment using Python {python_version}, but 3.12.3 is recommended."
                )
        except Exception as exc:  # noqa: BLE001 - must mirror legacy behaviour
            deps.telemetry_capture_exception(exc)
            deps.print_warning(
                f"Found virtual environment, but couldn't verify Python version: {exc}"
            )
        return adscan_venv_ok, all_ok

    deps.print_error(f"Virtual environment not found at {config.venv_path}.")
    if not config.fix_mode:
        return False, False

    deps.print_info("Attempting to create the ADscan virtual environment (--fix)...")
    try:
        if not deps.ensure_dir_writable(
            config.adscan_base_dir,
            description="ADscan base",
            fix=True,
            recursive=True,
        ):
            deps.print_error(
                "Cannot create the virtual environment because the ADscan base directory is not writable."
            )
            deps.print_instruction(
                f'Run: sudo chown -R $USER:$USER "{config.adscan_base_dir}"'
            )
            return False, False

        ok, _, _ = deps.install_pyenv_python_and_venv(
            python_version="3.12.3",
            venv_path=config.venv_path,
        )
        if ok and deps.path_exists(venv_python):
            deps.print_success(f"Virtual environment created: {config.venv_path}")
            return True, all_ok

        deps.print_error("Failed to create the virtual environment automatically.")
        return False, False
    except Exception as exc:  # noqa: BLE001 - legacy catch-all for installation attempts
        deps.telemetry_capture_exception(exc)
        deps.print_error("Failed to create the virtual environment automatically.")
        if deps.print_exception is not None:
            deps.print_exception(show_locals=False, exception=exc)
        return False, False


@dataclass(frozen=True)
class CoreDepsCheckConfig:
    """Configuration for checking core dependencies in system Python."""

    core_requirements: List[str]


@dataclass(frozen=True)
class CoreDepsCheckDeps:
    """Dependency bundle for core dependency checks."""

    run_command: Callable[..., object]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    parse_requirement_spec: Callable[[str], Dict[str, Any]]
    get_python_package_version: Callable[[str, str], str | None]
    assess_version_compliance: Callable[..., tuple[str, str]]
    get_installed_vcs_reference: Callable[..., Dict[str, Any] | None]
    get_installed_vcs_reference_by_url: Callable[..., Dict[str, Any] | None]
    normalize_vcs_repo_url: Callable[[str], str]
    vcs_reference_matches: Callable[[str | None, str | None], bool]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_success: Callable[[str], None]
    print_success_verbose: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    telemetry_capture_exception: Callable[[BaseException], None]


def check_core_dependencies(
    *,
    config: CoreDepsCheckConfig,
    deps: CoreDepsCheckDeps,
) -> bool:
    """Check that core dependencies are installed and at expected versions."""
    deps.print_info("Checking core dependencies in system Python...")

    # Find system python3 executable (same logic as handle_install)
    system_python = shutil.which("python3")
    if not system_python:
        # Fallback to sys.executable if python3 not found (but this might be PyInstaller binary)
        system_python = sys.executable
        deps.print_warning("python3 not found in PATH, using sys.executable")

    if not system_python:
        deps.print_warning(
            "Could not determine system Python executable for core dependencies verification"
        )
        return False

    deps.print_info_verbose(f"Verifying core dependencies using: {system_python}")
    core_requirements = config.core_requirements
    missing_core_deps: List[str] = []
    core_version_issues: List[str] = []

    clean_env = deps.get_clean_env_for_compilation()

    for dep in core_requirements:
        spec_info = deps.parse_requirement_spec(dep)
        package_name = spec_info.get("package_name") or dep
        try:
            import_name = package_name.replace("-", "_")
            result = deps.run_command(
                [system_python, "-c", f"import {import_name}"],
                capture_output=True,
                check=False,
                env=clean_env,
            )
            if result.returncode == 0:
                deps.print_success_verbose(
                    f"Core dependency '{package_name}' is installed in system Python"
                )
                installed_version = deps.get_python_package_version(
                    system_python, package_name
                )
                specifier = spec_info.get("specifier")
                enforce_latest = specifier is None and not spec_info.get(
                    "is_vcs", False
                )
                status, message = deps.assess_version_compliance(
                    package_name,
                    installed_version,
                    specifier=specifier,
                    enforce_latest=enforce_latest,
                )
                if status == "error":
                    deps.print_error(message)
                    core_version_issues.append(message)
                elif status == "warning":
                    deps.print_warning(message)
                else:
                    deps.print_success_verbose(message)

                expected_vcs_ref = spec_info.get("vcs_reference")
                if spec_info.get("is_vcs") and expected_vcs_ref:
                    vcs_meta = deps.get_installed_vcs_reference(
                        system_python, package_name
                    )
                    if not vcs_meta:
                        repo_url = spec_info.get("vcs_url")
                        normalized_url = (
                            deps.normalize_vcs_repo_url(repo_url) if repo_url else None
                        )
                        if normalized_url:
                            vcs_meta = deps.get_installed_vcs_reference_by_url(
                                system_python, normalized_url
                            )
                    commit_id = None
                    if vcs_meta:
                        commit_id = vcs_meta.get("commit_id") or vcs_meta.get(
                            "requested_revision"
                        )
                    if deps.vcs_reference_matches(commit_id, expected_vcs_ref):
                        short_commit = commit_id[:12] if commit_id else "unknown"
                        deps.print_success_verbose(
                            f"{package_name} matches expected VCS reference "
                            f"{expected_vcs_ref} (installed {short_commit})"
                        )
                    else:
                        if commit_id:
                            issue = (
                                f"{package_name} VCS reference mismatch "
                                f"(expected {expected_vcs_ref}, got {commit_id})"
                            )
                            deps.print_error(issue)
                            core_version_issues.append(issue)
                        else:
                            warning = (
                                f"{package_name} is installed from VCS but its commit "
                                f"could not be determined (expected {expected_vcs_ref})."
                            )
                            deps.print_warning(warning)
            else:
                deps.print_error(
                    f"Core dependency '{package_name}' is NOT installed in system Python"
                )
                missing_core_deps.append(package_name)
        except Exception as exc:  # noqa: BLE001
            deps.telemetry_capture_exception(exc)
            deps.print_warning(
                f"Could not verify core dependency '{package_name}': {exc}"
            )
            missing_core_deps.append(package_name)

    all_ok = True
    if missing_core_deps:
        deps.print_error(
            "Missing core dependencies in system Python: "
            + ", ".join(missing_core_deps)
        )
        deps.print_instruction(
            "Run: adscan install (will install core dependencies in system Python)"
        )
        all_ok = False
    if core_version_issues:
        deps.print_error("Core dependency version mismatches detected.")
        for issue in core_version_issues:
            deps.print_error(f"  - {issue}")
        deps.print_instruction(
            "Run: adscan install (will synchronize core dependency versions)"
        )
        all_ok = False
    if not missing_core_deps and not core_version_issues:
        deps.print_success("All core dependencies are installed in system Python")

    return all_ok


# ─── Go Toolchain / htb-cli Check ──────────────────────────────────────────


@dataclass(frozen=True)
class GoToolchainCheckConfig:
    """Configuration for Go toolchain and htb-cli checks."""

    full_container_runtime: bool
    fix_mode: bool
    session_env: str


@dataclass(frozen=True)
class GoToolchainCheckDeps:
    """Dependency bundle for Go toolchain and htb-cli checks."""

    # Go helpers
    configure_go_official_path: Callable[[], None]
    configure_go_path: Callable[[], None]
    is_go_available: Callable[[os._Environ[str]], tuple[bool, str]]
    is_go_bin_in_path: Callable[[], tuple[bool, str | None]]

    # htb-cli helpers
    is_htb_cli_installed: Callable[[], tuple[bool, str | None]]
    is_htb_cli_accessible: Callable[[], tuple[bool, str | None]]

    # System helpers
    os_environ: os._Environ[str]
    subprocess_run: Callable[..., subprocess.CompletedProcess[str]]

    # Output
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]


def check_go_toolchain(
    *, config: GoToolchainCheckConfig, deps: GoToolchainCheckDeps
) -> bool:
    """Check Go toolchain and (in CI) htb-cli installation/accessibility."""

    if config.full_container_runtime:
        deps.print_info(
            "Skipping Go toolchain and htb-cli verification (running in container)."
        )
        return True

    all_ok = True
    deps.print_info("Checking Go toolchain...")

    if config.fix_mode:
        deps.configure_go_official_path()
        if config.session_env == "ci":
            deps.configure_go_path()

    go_available, go_version = deps.is_go_available(deps.os_environ)
    if go_available:
        deps.print_success(f"Go found: {go_version}")

        go_path_check = deps.subprocess_run(
            ["which", "go"], capture_output=True, text=True, check=False
        )
        if go_path_check.returncode == 0:
            go_binary_path = go_path_check.stdout.strip()
            if "/usr/local/go/bin/go" in go_binary_path:
                deps.print_info(
                    "Go is installed from official golang.org source (latest version)"
                )
            else:
                deps.print_warning(
                    "Go appears to be installed via system package manager (apt)"
                )
                deps.print_info(
                    "   Consider installing from official source for latest version:"
                )
                deps.print_info(
                    "   Run: adscan install (will install Go from golang.org)"
                )
    else:
        deps.print_warning("Go not found")
        deps.print_info(
            "   Install with: adscan install (will install Go from official golang.org source)"
        )
        deps.print_info(
            "   Or manually: curl -L https://go.dev/dl/go1.23.4.linux-amd64.tar.gz | sudo tar -C /usr/local -xzf -"
        )
        all_ok = False

    if config.session_env != "ci":
        deps.print_info_verbose(
            f"Skipping htb-cli verification in environment '{config.session_env}' (CI-only)."
        )
        return all_ok

    # CI-only htb-cli checks
    deps.print_info("Checking htb-cli...")

    htb_cli_installed, htb_cli_path = deps.is_htb_cli_installed()
    if htb_cli_installed:
        deps.print_success(f"htb-cli binary found at: {htb_cli_path}")
    else:
        deps.print_warning(
            f"htb-cli binary not found at expected location: {htb_cli_path}"
        )
        deps.print_info(
            "   Install with: go install github.com/GoToolSharing/htb-cli@latest"
        )
        deps.print_info(
            "   Or run: adscan install (will install htb-cli automatically)"
        )
        all_ok = False

    go_bin_in_path, _ = deps.is_go_bin_in_path()
    if go_bin_in_path:
        deps.print_success("~/go/bin is in PATH")
    else:
        deps.print_warning("~/go/bin not found in PATH")
        deps.print_info("   Run: adscan install (will configure PATH automatically)")
        deps.print_info("   Or manually add to your shell config:")
        deps.print_info('   export PATH="$HOME/go/bin:$PATH"')

    htb_cli_accessible, _ = deps.is_htb_cli_accessible()
    if htb_cli_accessible:
        deps.print_success("htb-cli is accessible in PATH")
    else:
        if htb_cli_installed:
            deps.print_warning(
                "htb-cli binary exists but may not be accessible until terminal restart"
            )
            deps.print_info(
                "   Try restarting your terminal or run: source ~/.bashrc (or ~/.zshrc)"
            )
        else:
            deps.print_warning("htb-cli is not accessible")
            deps.print_info(
                "   Install with: go install github.com/GoToolSharing/htb-cli@latest"
            )

    if htb_cli_installed and htb_cli_accessible:
        deps.print_success("htb-cli is installed and accessible")
    elif htb_cli_installed:
        deps.print_warning(
            "htb-cli is installed but may require terminal restart to access"
        )
    else:
        deps.print_warning("htb-cli is not installed")
        deps.print_info("   Run: adscan install (will install htb-cli automatically)")
        all_ok = False

    return all_ok


@dataclass(frozen=True)
class ExternalToolsCheckConfig:
    """Configuration for checking external Python tools in isolated venvs."""

    pip_tools_config: Mapping[str, Dict[str, Any]]
    tool_venvs_base_dir: str
    fix_mode: bool


@dataclass(frozen=True)
class ExternalToolsCheckDeps:
    """Dependency bundle for external Python tools checks."""

    run_command: Callable[..., subprocess.CompletedProcess]
    parse_requirement_spec: Callable[[str], Dict[str, Any]]
    build_venv_exec_env: Callable[..., Dict[str, str]]
    check_executable_help_works: Callable[..., bool]
    fix_isolated_python_tool_venv: Callable[[str], bool]
    diagnose_manspider_help_failure: Callable[..., None]
    ensure_isolated_tool_extra_specs_installed: Callable[..., bool]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    get_python_package_version: Callable[..., str | None]
    assess_version_compliance: Callable[..., tuple[str, str]]
    get_installed_vcs_reference: Callable[..., Dict[str, Any] | None]
    get_installed_vcs_reference_by_url: Callable[..., Dict[str, Any] | None]
    normalize_vcs_repo_url: Callable[[str], str]
    vcs_reference_matches: Callable[[str | None, str | None], bool]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_success: Callable[[str], None]
    print_success_verbose: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    telemetry_capture_exception: Callable[[BaseException], None]


def check_external_tools(
    *,
    config: ExternalToolsCheckConfig,
    deps: ExternalToolsCheckDeps,
) -> bool:
    """Check that external Python tools in their isolated venvs are healthy."""
    deps.print_info("Checking external Python tools in their isolated environments...")

    missing_tools: List[str] = []
    tool_version_issues: List[str] = []
    all_ok = True

    for tool_key, tool_cfg in config.pip_tools_config.items():
        tool_dir_name = tool_key
        check_target = tool_cfg["check_target"]
        check_type = tool_cfg["check_type"]
        spec_info = deps.parse_requirement_spec(tool_cfg["spec"])
        extra_specs = tool_cfg.get("extra_specs", [])
        specifier = spec_info.get("specifier")
        enforce_latest = specifier is None and not spec_info.get("is_vcs", False)
        requirement_package = spec_info.get("package_name")

        tool_specific_venv_path = os.path.join(
            config.tool_venvs_base_dir, tool_dir_name, "venv"
        )
        tool_specific_python = os.path.join(tool_specific_venv_path, "bin", "python")
        tool_specific_executable = os.path.join(
            tool_specific_venv_path,
            "bin",
            check_target if check_type == "executable" else "",
        )
        tool_failed = False

        if not os.path.exists(tool_specific_venv_path):
            deps.print_error(
                f"Missing venv for {tool_dir_name} at {tool_specific_venv_path}"
            )
            if config.fix_mode and deps.fix_isolated_python_tool_venv(tool_dir_name):
                deps.print_success(f"{tool_dir_name}: venv recreated successfully.")
            else:
                missing_tools.append(f"{tool_dir_name} (venv missing)")
                all_ok = False
                continue
        elif config.fix_mode and extra_specs:
            deps.ensure_isolated_tool_extra_specs_installed(
                tool_name=tool_dir_name,
                tool_python=tool_specific_python,
                venv_path=tool_specific_venv_path,
                extra_specs=extra_specs,
            )

        if check_type == "executable":
            if os.path.exists(tool_specific_executable) and os.access(
                tool_specific_executable, os.X_OK
            ):
                deps.print_success(
                    f"Tool {tool_dir_name} ({check_target}) executable found."
                )
                exec_env = deps.build_venv_exec_env(
                    venv_path=tool_specific_venv_path,
                    python_executable=tool_specific_python,
                )
                help_ok = deps.check_executable_help_works(
                    tool_name=tool_dir_name,
                    executable_path=tool_specific_executable,
                    env=exec_env,
                    fix=config.fix_mode,
                )
                if not help_ok and config.fix_mode:
                    deps.print_warning(
                        f"{tool_dir_name} failed its help probe; attempting to recreate its isolated venv..."
                    )
                    if deps.fix_isolated_python_tool_venv(tool_dir_name):
                        exec_env = deps.build_venv_exec_env(
                            venv_path=tool_specific_venv_path,
                            python_executable=tool_specific_python,
                        )
                        help_ok = deps.check_executable_help_works(
                            tool_name=tool_dir_name,
                            executable_path=tool_specific_executable,
                            env=exec_env,
                            fix=False,
                        )

                if not help_ok:
                    if tool_dir_name == "manspider":
                        deps.diagnose_manspider_help_failure(
                            tool_python=tool_specific_python,
                            env=exec_env,
                        )
                    deps.print_error(
                        f"{tool_dir_name}: executable exists but failed to run (--help/-h)."
                    )
                    missing_tools.append(f"{tool_dir_name} (executable broken)")
                    all_ok = False
                    tool_failed = True
            else:
                deps.print_error(
                    f"Tool {tool_dir_name} ({check_target}) executable NOT found or not executable at {tool_specific_executable}"  # noqa: E501
                )
                if config.fix_mode and deps.fix_isolated_python_tool_venv(
                    tool_dir_name
                ):
                    deps.print_success(
                        f"{tool_dir_name}: reinstalled; re-run `adscan check` to verify."
                    )
                else:
                    missing_tools.append(f"{tool_dir_name} ({check_target} executable)")
                all_ok = False
                tool_failed = True
        elif check_type == "module":
            env = deps.build_venv_exec_env(
                venv_path=tool_specific_venv_path,
                python_executable=tool_specific_python,
            )
            try:
                deps.run_command(
                    [tool_specific_python, "-c", f"import {check_target}"],
                    capture_output=True,
                    check=True,
                    env=env,
                )
                deps.print_success(
                    f"Tool {tool_dir_name} (module {check_target}) importable."
                )
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                if config.fix_mode:
                    deps.print_warning(
                        f"{tool_dir_name} import check failed; attempting to recreate its isolated venv..."  # noqa: E501
                    )
                    if deps.fix_isolated_python_tool_venv(tool_dir_name):
                        env = deps.build_venv_exec_env(
                            venv_path=tool_specific_venv_path,
                            python_executable=tool_specific_python,
                        )
                        try:
                            deps.run_command(
                                [tool_specific_python, "-c", f"import {check_target}"],
                                capture_output=True,
                                check=True,
                                env=env,
                            )
                            deps.print_success(
                                f"Tool {tool_dir_name} (module {check_target}) importable after repair."  # noqa: E501
                            )
                            continue
                        except (subprocess.CalledProcessError, FileNotFoundError):
                            pass

                error_message = str(exc)
                if (
                    isinstance(exc, subprocess.CalledProcessError)
                    and exc.returncode < 0
                ):
                    try:
                        signal_name = signal.Signals(-exc.returncode).name
                        error_message = f"Command died with <Signals.{signal_name}: {-exc.returncode}>."
                    except Exception:  # noqa: BLE001
                        error_message = f"Command died with signal {-exc.returncode}."

                if isinstance(exc, subprocess.CalledProcessError):
                    if exc.stdout:
                        error_message += f"\nStdout: {exc.stdout.strip()}"
                    if exc.stderr:
                        error_message += f"\nStderr: {exc.stderr.strip()}"

                deps.print_error(
                    f"Tool {tool_dir_name} (module {check_target}) NOT importable using {tool_specific_python}. Error: {error_message}"  # noqa: E501
                )
                missing_tools.append(f"{tool_dir_name} (module {check_target})")
                all_ok = False
                tool_failed = True
        else:
            deps.print_warning(
                f"Unknown check_type '{check_type}' for tool {tool_dir_name}. Skipping check."
            )
            tool_failed = True
            all_ok = False

        if (
            not tool_failed
            and requirement_package
            and os.path.exists(tool_specific_python)
            and (specifier or enforce_latest or spec_info.get("is_vcs"))
        ):
            version_env = deps.get_clean_env_for_compilation()
            version_env["VIRTUAL_ENV"] = tool_specific_venv_path
            tool_bin_path = os.path.dirname(tool_specific_python)
            version_env["PATH"] = (
                f"{tool_bin_path}{os.pathsep}{version_env.get('PATH', '')}"
            )
            version_env.pop("PYTHONHOME", None)
            version_env.pop("PYTHONPATH", None)

            if specifier or enforce_latest:
                installed_version = deps.get_python_package_version(
                    tool_specific_python,
                    requirement_package,
                    env=version_env,
                )
                status, message = deps.assess_version_compliance(
                    requirement_package,
                    installed_version,
                    specifier=specifier,
                    enforce_latest=enforce_latest,
                )
                if status == "error":
                    if config.fix_mode and deps.fix_isolated_python_tool_venv(
                        tool_dir_name
                    ):
                        deps.print_warning(
                            f"{tool_dir_name}: {message} (attempting --fix reinstall to satisfy requirement)"  # noqa: E501
                        )
                        installed_version = deps.get_python_package_version(
                            tool_specific_python,
                            requirement_package,
                            env=version_env,
                        )
                        status, message = deps.assess_version_compliance(
                            requirement_package,
                            installed_version,
                            specifier=specifier,
                            enforce_latest=enforce_latest,
                        )
                    if status == "error":
                        issue_message = f"{tool_dir_name}: {message}"
                        deps.print_error(issue_message)
                        tool_version_issues.append(issue_message)
                        all_ok = False
                elif status == "warning":
                    deps.print_warning(f"{tool_dir_name}: {message}")
                else:
                    deps.print_success_verbose(f"{tool_dir_name}: {message}")

            expected_vcs_ref = spec_info.get("vcs_reference")
            if spec_info.get("is_vcs") and expected_vcs_ref:
                vcs_meta = deps.get_installed_vcs_reference(
                    tool_specific_python,
                    requirement_package,
                    env=version_env,
                )
                if not vcs_meta:
                    repo_url = spec_info.get("vcs_url")
                    normalized_url = (
                        deps.normalize_vcs_repo_url(repo_url) if repo_url else None
                    )
                    if normalized_url:
                        vcs_meta = deps.get_installed_vcs_reference_by_url(
                            tool_specific_python,
                            normalized_url,
                            env=version_env,
                        )
                commit_id = None
                if vcs_meta:
                    commit_id = vcs_meta.get("commit_id") or vcs_meta.get(
                        "requested_revision"
                    )
                if deps.vcs_reference_matches(commit_id, expected_vcs_ref):
                    short_commit = commit_id[:12] if commit_id else "unknown"
                    deps.print_success_verbose(
                        f"{tool_dir_name}: VCS reference matches {expected_vcs_ref} (installed {short_commit})"  # noqa: E501
                    )
                else:
                    issue_message = (
                        f"{tool_dir_name}: installed from VCS but commit could not be determined "
                        f"(expected {expected_vcs_ref})."
                    )
                    deps.print_warning(issue_message)

    if missing_tools:
        deps.print_error(
            "Issues found with external Python tools: " + ", ".join(missing_tools)
        )
        deps.print_instruction("Try: adscan check --fix")
        all_ok = False
    if tool_version_issues:
        deps.print_error("Version mismatches detected for external Python tools.")
        for issue in tool_version_issues:
            deps.print_error(f"  - {issue}")
        deps.print_instruction("Try: adscan check --fix")
        all_ok = False
    if not missing_tools and not tool_version_issues and all_ok:
        deps.print_success(
            "All key external Python tools seem to be correctly installed in their isolated environments."  # noqa: E501
        )

    return all_ok


@dataclass(frozen=True)
class SystemPackagesCheckConfig:
    """Configuration for checking essential system packages."""

    system_packages_to_verify: Mapping[str, Dict[str, Any]]
    fix_mode: bool
    full_container_runtime: bool = False


@dataclass(frozen=True)
class SystemPackagesCheckDeps:
    """Dependency bundle for system packages verification."""

    verify_system_packages: Callable[..., Dict[str, Any]]
    run_command: Callable[..., subprocess.CompletedProcess]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    apply_effective_user_home_to_env: Callable[[Dict[str, str]], None]
    sudo_validate: Callable[[], bool]
    print_info: Callable[[str], None]
    print_info_debug: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    telemetry_capture_exception: Callable[[BaseException], None]
    print_exception: Callable[..., None]


def check_system_packages(
    *,
    config: SystemPackagesCheckConfig,
    deps: SystemPackagesCheckDeps,
) -> tuple[bool, List[str]]:
    """Check essential system packages and optionally attempt --fix via apt-get."""
    deps.print_info("Checking for essential system packages...")
    package_results = deps.verify_system_packages(
        config.system_packages_to_verify, mode="check"
    )

    missing_pkgs = list(package_results.get("missing", []))
    missing_pkgs, package_issues = _normalize_missing_system_packages_for_runtime(
        missing_pkgs=missing_pkgs,
        deps=deps,
    )
    if missing_pkgs:
        deps.print_info_debug(
            "[check] Missing system packages after runtime normalization: "
            + ", ".join(missing_pkgs)
        )
        deps.print_error(f"Missing system packages: {', '.join(missing_pkgs)}")
        if config.full_container_runtime:
            deps.print_instruction(
                "Run on the host: adscan update"
            )
            deps.print_info(
                "This check is running inside the ADscan runtime, so missing runtime-managed "
                "packages should be repaired by refreshing the host launcher/runtime image."
            )
        else:
            deps.print_instruction(
                f"Try installing them with: sudo apt install {' '.join(missing_pkgs)}"
            )

        if config.fix_mode:
            if config.full_container_runtime:
                deps.print_warning(
                    "Automatic system-package repair is not available inside the ADscan runtime."
                )
                return False, missing_pkgs
            if not shutil.which("apt-get"):
                deps.print_warning(
                    "Automatic package installation requires apt-get (Debian-based systems)."
                )
                return False, missing_pkgs
            if not deps.sudo_validate():
                deps.print_warning(
                    "Cannot auto-install system packages without sudo privileges."
                )
                return False, missing_pkgs
            try:
                deps.print_info(
                    "Attempting to install missing system packages (requested via --fix)..."
                )
                install_env = deps.get_clean_env_for_compilation()
                deps.apply_effective_user_home_to_env(install_env)
                install_env.setdefault("DEBIAN_FRONTEND", "noninteractive")
                install_env.setdefault("NEEDRESTART_MODE", "a")

                deps.run_command(
                    ["sudo", "apt-get", "update"],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=install_env,
                    timeout=600,
                )
                deps.run_command(
                    ["sudo", "apt-get", "install", "-y"] + missing_pkgs,
                    check=True,
                    capture_output=True,
                    text=True,
                    env=install_env,
                    timeout=1800,
                )
                # Re-verify
                package_results = deps.verify_system_packages(
                    config.system_packages_to_verify, mode="check"
                )
                if package_results.get("missing"):
                    deps.print_error(
                        "Some system packages are still missing after --fix: "
                        + ", ".join(package_results["missing"])
                    )
                    return False, list(package_results["missing"])
                deps.print_success(
                    "Essential system packages installed successfully (--fix)."
                )
                return True, []
            except subprocess.CalledProcessError as exc:
                deps.telemetry_capture_exception(exc)
                deps.print_error(
                    "Failed to install missing system packages with --fix."
                )
                deps.print_exception(show_locals=False, exception=exc)
                return False, missing_pkgs
            except Exception as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                deps.print_error(
                    "Unexpected error while attempting to install system packages (--fix)."
                )
                deps.print_exception(show_locals=False, exception=exc)
                return False, missing_pkgs
        return False, missing_pkgs

    if package_issues:
        deps.print_error("System package validation issues detected:")
        for issue in package_issues:
            deps.print_error(f"  - {issue}")
        if any("John the Ripper" in issue for issue in package_issues):
            if config.full_container_runtime:
                deps.print_instruction(
                    "Run on the host: adscan update (refreshes the runtime image with the compatible John wrapper build)."
                )
            else:
                deps.print_instruction(
                    "Refresh ADscan so John the Ripper is rebuilt with a compatible CPU baseline or wrapper."
                )
        else:
            deps.print_instruction(
                "Install a working hashcat binary via PATH (>= 7.1.2), for example from the official release."
            )
        return False, []

    deps.print_success("Essential system packages seem to be installed.")
    return True, []


@dataclass(frozen=True)
class LibreOfficeCheckConfig:
    """Configuration for checking LibreOffice availability (none needed)."""


@dataclass(frozen=True)
class LibreOfficeCheckDeps:
    """Dependency bundle for LibreOffice check."""

    is_libreoffice_available: Callable[[], tuple[bool, str]]
    print_info: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_instruction: Callable[[str], None]


def check_libreoffice(
    *,
    config: LibreOfficeCheckConfig,
    deps: LibreOfficeCheckDeps,
) -> bool:
    """Check whether LibreOffice is available for PDF report generation.

    Returns:
        True if libreoffice is present, False otherwise. Note: this is optional and
        should not fail the overall check on its own.
    """
    deps.print_info("Checking libreoffice for PDF conversion...")
    libreoffice_available, libreoffice_info = deps.is_libreoffice_available()
    if libreoffice_available:
        deps.print_success(f"libreoffice is available: {libreoffice_info}")
        return True
    deps.print_warning(f"libreoffice is not available: {libreoffice_info}")
    deps.print_info("libreoffice is required for PDF report generation")
    deps.print_instruction("Install with: sudo apt-get install -y libreoffice")
    return False


@dataclass(frozen=True)
class ExternalBinaryToolsCheckConfig:
    """Configuration for checking non-Python external tools (files on disk)."""

    external_tools_config: Mapping[str, Dict[str, Any]]
    tools_install_dir: str
    venv_path: str
    full_container_runtime: bool
    fix_mode: bool


@dataclass(frozen=True)
class ExternalBinaryToolsCheckDeps:
    """Dependency bundle for external binary tools verification."""

    expand_effective_user_path: Callable[[str], str]
    preflight_install_dns: Callable[..., bool]
    setup_external_tool: Callable[..., bool]
    print_info: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]


def check_external_binary_tools(
    *,
    config: ExternalBinaryToolsCheckConfig,
    deps: ExternalBinaryToolsCheckDeps,
) -> tuple[bool, list[str]]:
    """Check presence of external binary tools and optionally attempt --fix reinstall."""
    deps.print_info("Checking for external tools...")
    external_tools_to_verify: Dict[str, str] = {}
    external_tool_check_to_base: Dict[str, str] = {}

    for tool_name, tool_cfg in config.external_tools_config.items():
        # Conditional checks (skip in CE or legacy depending on metadata)
        if "condition" in tool_cfg:
            # Only known condition used in current code is "legacy_only"
            # The caller should pre-filter mode; we keep the key here for parity.
            pass

        # Multiple check paths (e.g., PKINITtools)
        if "check_paths" in tool_cfg:
            for check_path in tool_cfg["check_paths"]:
                check_name = (
                    f"{tool_name}_{check_path.split('/')[-1].replace('.py', '')}"
                )
                external_tools_to_verify[check_name] = os.path.join(
                    config.tools_install_dir, check_path
                )
                external_tool_check_to_base[check_name] = tool_name
        elif "check_path" in tool_cfg:
            check_path = tool_cfg["check_path"]
            if check_path.startswith("~"):
                external_tools_to_verify[tool_name] = deps.expand_effective_user_path(
                    check_path
                )
                external_tool_check_to_base[tool_name] = tool_name
            elif check_path.startswith("/"):
                external_tools_to_verify[tool_name] = check_path
                external_tool_check_to_base[tool_name] = tool_name
            else:
                external_tools_to_verify[tool_name] = os.path.join(
                    config.tools_install_dir, check_path
                )
                external_tool_check_to_base[tool_name] = tool_name

        # Optional venv-link check (not applicable in full container runtime)
        if tool_cfg.get("check_venv_link", False) and not config.full_container_runtime:
            binary_name = tool_cfg.get("name", tool_name)
            external_tools_to_verify[f"{tool_name}_venv_link"] = os.path.join(
                config.venv_path, "bin", binary_name
            )
            external_tool_check_to_base[f"{tool_name}_venv_link"] = tool_name

    missing_checks: list[str] = []
    missing_bases: set[str] = set()

    for tool_check_name, tool_path in external_tools_to_verify.items():
        if os.path.exists(tool_path):
            deps.print_success(f"{tool_check_name} found at {tool_path}")
            continue
        missing_checks.append(tool_check_name)
        missing_bases.add(
            external_tool_check_to_base.get(tool_check_name, tool_check_name)
        )

    if missing_checks and config.fix_mode:
        deps.print_info("Attempting to install missing external tools (--fix)...")
        github_ok = deps.preflight_install_dns(
            ["github.com"],
            attempts=2,
            backoff_seconds=2,
            context_label="check --fix external tools",
        )
        for base_tool in sorted(missing_bases):
            tool_cfg = config.external_tools_config.get(base_tool)
            if not tool_cfg:
                continue
            deps.print_info(f"Repairing external tool: {base_tool} (--fix)...")
            # setup_external_tool(name, config, github_dns_ok, force_reinstall)
            deps.setup_external_tool(
                base_tool, tool_cfg, github_dns_ok=github_ok, force_reinstall=False
            )

        # Re-check after fix attempt
        still_missing: list[str] = []
        for tool_check_name in missing_checks:
            tool_path = external_tools_to_verify.get(tool_check_name)
            if tool_path and os.path.exists(tool_path):
                deps.print_success(f"{tool_check_name} found at {tool_path}")
            else:
                deps.print_error(
                    f"{tool_check_name} not found at {tool_path}. Try reinstalling."
                )
                still_missing.append(tool_check_name)
        return (len(still_missing) == 0), still_missing

    # No fix mode or nothing missing
    return (len(missing_checks) == 0), missing_checks


def _normalize_missing_system_packages_for_runtime(
    *,
    missing_pkgs: list[str],
    deps: SystemPackagesCheckDeps,
) -> tuple[list[str], list[str]]:
    """Drop false positives for packages replaced by runtime-managed tools.

    Some container/runtime environments intentionally provide tools outside the
    distro package database. We keep the package in the install config for
    host-based installs, but during checks we should not fail if a working tool
    is available via PATH.
    """
    normalized_missing = list(missing_pkgs)
    issues: list[str] = []

    if "john" in normalized_missing:
        john_executable = None
        preferred_runtime_john = "/opt/adscan/tools/john/run/john"
        if os.path.exists(preferred_runtime_john):
            john_executable = preferred_runtime_john
            deps.print_info_debug(
                f"[check] Found preferred runtime john candidate: {preferred_runtime_john}"
            )
        else:
            which_john = shutil.which("john")
            if which_john:
                john_executable = os.path.realpath(which_john)
                deps.print_info_debug(
                    f"[check] Found john via PATH candidate: {john_executable}"
                )
            else:
                deps.print_info_debug(
                    "[check] John the Ripper not found in preferred runtime path or PATH."
                )

        if john_executable:
            try:
                result = deps.run_command(
                    [john_executable, "--list=build-info"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except Exception as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                deps.print_info_debug(
                    f"[check] Failed to probe john candidate {john_executable}: {exc}"
                )
            else:
                if result and getattr(result, "returncode", 1) == 0:
                    deps.print_success(
                        f"John the Ripper is available via PATH ({john_executable})"
                    )
                    normalized_missing.remove("john")
                    issues.extend(
                        _validate_runtime_managed_john_converters(
                            john_executable=john_executable,
                            deps=deps,
                        )
                    )
                else:
                    stdout_text = (getattr(result, "stdout", "") or "").strip()
                    stderr_text = (getattr(result, "stderr", "") or "").strip()
                    deps.print_info_debug(
                        "[check] John candidate did not pass build-info probe: "
                        f"path={john_executable}, returncode={getattr(result, 'returncode', None)}, "
                        f"stdout={stdout_text[:200]!r}, "
                        f"stderr={stderr_text[:200]!r}"
                    )
                    if _JOHN_AVX2_REQUIRED_RE.search(stdout_text) or _JOHN_AVX2_REQUIRED_RE.search(
                        stderr_text
                    ):
                        issues.append(
                            "John the Ripper is present but incompatible with the CPU exposed by this host/VM "
                            "(the current binary requires AVX2)."
                        )
                        normalized_missing.remove("john")

    if "hashcat" in normalized_missing:
        hashcat_executable = shutil.which("hashcat")
        if hashcat_executable:
            hashcat_executable = os.path.realpath(hashcat_executable)
            try:
                result = deps.run_command(
                    [hashcat_executable, "--version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except Exception as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
            else:
                combined_output = "\n".join(
                    [
                        getattr(result, "stdout", "") or "",
                        getattr(result, "stderr", "") or "",
                    ]
                ).strip()
                parsed_version = _parse_hashcat_version(combined_output)
                if (
                    result
                    and getattr(result, "returncode", 1) == 0
                    and parsed_version is not None
                    and parsed_version >= _MINIMUM_HASHCAT_VERSION
                ):
                    version_text = ".".join(str(part) for part in parsed_version)
                    deps.print_success(
                        f"Hashcat is available via PATH ({hashcat_executable}, v{version_text})"
                    )
                    normalized_missing.remove("hashcat")
                else:
                    minimum = ".".join(str(part) for part in _MINIMUM_HASHCAT_VERSION)
                    detected_version = (
                        ".".join(str(part) for part in parsed_version)
                        if parsed_version is not None
                        else "unknown"
                    )
                    issues.append(
                        "hashcat is available via PATH "
                        f"({hashcat_executable}) but version {detected_version} does not meet "
                        f"the minimum required version {minimum}"
                    )
                    normalized_missing.remove("hashcat")

    if "freerdp3-x11" in normalized_missing:
        freerdp_executable = shutil.which("xfreerdp") or shutil.which("xfreerdp3")
        if freerdp_executable:
            freerdp_executable = os.path.realpath(freerdp_executable)
            try:
                result = deps.run_command(
                    [freerdp_executable, "--version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except Exception as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                deps.print_info_debug(
                    f"[check] Failed to probe FreeRDP candidate {freerdp_executable}: {exc}"
                )
            else:
                if result and getattr(result, "returncode", 1) == 0:
                    combined_output = "\n".join(
                        [
                            getattr(result, "stdout", "") or "",
                            getattr(result, "stderr", "") or "",
                        ]
                    ).strip()
                    deps.print_success(
                        "FreeRDP is available via PATH "
                        f"({freerdp_executable}, {combined_output or 'version detected'})"
                    )
                    normalized_missing.remove("freerdp3-x11")
                else:
                    deps.print_info_debug(
                        "[check] FreeRDP candidate did not pass version probe: "
                        f"path={freerdp_executable}, returncode={getattr(result, 'returncode', None)}, "
                        f"stdout={(getattr(result, 'stdout', '') or '').strip()[:200]!r}, "
                        f"stderr={(getattr(result, 'stderr', '') or '').strip()[:200]!r}"
                    )

    if "medusa" in normalized_missing:
        medusa_executable = shutil.which("medusa")
        if medusa_executable:
            medusa_executable = os.path.realpath(medusa_executable)
            try:
                result = deps.run_command(
                    [medusa_executable, "-d"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except Exception as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                deps.print_info_debug(
                    f"[check] Failed to probe Medusa candidate {medusa_executable}: {exc}"
                )
            else:
                combined_output = "\n".join(
                    [
                        getattr(result, "stdout", "") or "",
                        getattr(result, "stderr", "") or "",
                    ]
                ).strip()
                if (
                    result
                    and getattr(result, "returncode", 1) == 0
                    and "rdp" in combined_output.lower()
                ):
                    deps.print_success(
                        "Medusa is available via PATH "
                        f"({medusa_executable}, RDP module detected)"
                    )
                    normalized_missing.remove("medusa")
                else:
                    deps.print_info_debug(
                        "[check] Medusa candidate did not pass module probe: "
                        f"path={medusa_executable}, returncode={getattr(result, 'returncode', None)}, "
                        f"stdout={(getattr(result, 'stdout', '') or '').strip()[:200]!r}, "
                        f"stderr={(getattr(result, 'stderr', '') or '').strip()[:200]!r}"
                    )

    return normalized_missing, issues


def _parse_hashcat_version(output: str) -> tuple[int, int, int] | None:
    """Extract a semantic version tuple from ``hashcat --version`` output."""

    match = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)\b", output)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _process_has_cap_net_admin() -> bool:
    """Return whether the current process has CAP_NET_ADMIN in its effective set."""

    return process_has_capability(_CAP_NET_ADMIN_BIT)


def _process_has_cap_net_bind_service() -> bool:
    """Return whether the current process has CAP_NET_BIND_SERVICE in its effective set."""

    return process_has_capability(_CAP_NET_BIND_SERVICE_BIT)


def _get_binary_capabilities(binary_path: str) -> str:
    """Return the raw `getcap` output for one binary, if available."""

    return get_binary_capabilities(binary_path)


def _binary_has_cap_net_admin(binary_path: str) -> bool:
    """Return whether one binary carries `cap_net_admin` file capabilities."""

    return binary_has_capability(binary_path, "cap_net_admin")


def _binary_has_cap_net_bind_service(binary_path: str) -> bool:
    """Return whether one binary carries `cap_net_bind_service` file capabilities."""

    return binary_has_capability(binary_path, "cap_net_bind_service")


def check_ligolo_ng_runtime_tooling(*, full_container_runtime: bool, deps: Any) -> bool:
    """Check the ligolo-ng binaries managed by the ADscan runtime.

    The Docker runtime should provide the local proxy binary. Windows agents
    can be cached ahead of time or fetched on demand later, so missing agent
    caches are informational rather than fatal.
    """
    deps.print_info("Checking ligolo-ng pivot tooling...")
    local_os, local_arch = get_current_ligolo_proxy_target()
    proxy_path = get_ligolo_proxy_local_path(target_os=local_os, arch=local_arch)
    if proxy_path is None:
        deps.print_error(
            f"ligolo-ng proxy v{LIGOLO_NG_VERSION} not found for {local_os}/{local_arch}."
        )
        if full_container_runtime:
            deps.print_instruction(
                "Update or rebuild the ADscan runtime image so the pinned ligolo-ng proxy is present."
            )
        else:
            deps.print_instruction(
                "Set ADSCAN_LIGOLO_PROXY_PATH or place the pinned ligolo-ng proxy under ~/.adscan/tools/ligolo-ng/."
            )
        return False

    if not os.access(proxy_path, os.X_OK):
        deps.print_error(f"ligolo-ng proxy is present but not executable: {proxy_path}")
        deps.print_instruction(f"Run: chmod +x {proxy_path}")
        return False

    deps.print_success(
        f"ligolo-ng proxy v{LIGOLO_NG_VERSION} available at {proxy_path} ({local_os}/{local_arch})"
    )

    if full_container_runtime:
        if not os.path.exists("/dev/net/tun"):
            deps.print_error(
                "ligolo-ng runtime support is incomplete: /dev/net/tun is not available in the container."
            )
            deps.print_instruction(
                "Update the launcher/runtime so docker runs include --device /dev/net/tun."
            )
            return False
        process_has_cap_net_admin = _process_has_cap_net_admin()
        process_has_cap_net_bind_service = _process_has_cap_net_bind_service()
        binary_capabilities = _get_binary_capabilities(str(proxy_path))
        binary_has_cap_net_admin = _binary_has_cap_net_admin(str(proxy_path))
        binary_has_cap_net_bind_service = _binary_has_cap_net_bind_service(str(proxy_path))
        print_info_debug = getattr(deps, "print_info_debug", None)
        if callable(print_info_debug):
            print_info_debug(
                "Ligolo capability diagnostics: "
                f"process_cap_net_admin={process_has_cap_net_admin} "
                f"process_cap_net_bind_service={process_has_cap_net_bind_service} "
                f"proxy_binary_capabilities={binary_capabilities or 'none'}"
            )
        if not process_has_cap_net_admin and not binary_has_cap_net_admin:
            deps.print_error(
                "ligolo-ng runtime support is incomplete: neither the ADscan process nor the ligolo-ng proxy binary has CAP_NET_ADMIN."
            )
            deps.print_instruction(
                "Update the launcher/runtime so docker runs include --cap-add NET_ADMIN or rebuild the runtime image with setcap cap_net_admin+ep on the ligolo proxy binary."
            )
            return False
        if not process_has_cap_net_bind_service and not binary_has_cap_net_bind_service:
            deps.print_error(
                "ligolo-ng runtime support is incomplete: neither the ADscan process nor the ligolo-ng proxy binary has CAP_NET_BIND_SERVICE."
            )
            deps.print_instruction(
                "Update the launcher/runtime so docker runs include --cap-add NET_BIND_SERVICE or rebuild the runtime image with "
                "setcap cap_net_admin,cap_net_bind_service+ep on the ligolo proxy binary."
            )
            return False
        if binary_has_cap_net_admin:
            deps.print_success(
                f"ligolo-ng proxy binary carries CAP_NET_ADMIN file capabilities ({binary_capabilities})."
            )
        elif process_has_cap_net_admin:
            deps.print_success(
                "ADscan process already has CAP_NET_ADMIN in its effective capability set."
            )
        if binary_has_cap_net_bind_service:
            deps.print_success(
                "ligolo-ng proxy binary carries CAP_NET_BIND_SERVICE file capabilities."
            )
        elif process_has_cap_net_bind_service:
            deps.print_success(
                "ADscan process already has CAP_NET_BIND_SERVICE in its effective capability set."
            )

    cached_windows_agent = get_ligolo_agent_local_path(target_os="windows", arch="amd64")
    if cached_windows_agent is not None:
        deps.print_success(
            "ligolo-ng Windows agent cache available at "
            f"{cached_windows_agent} (windows/amd64)"
        )
    else:
        deps.print_info(
            "ligolo-ng Windows agent cache is empty. ADscan will need to stage the required "
            "agent architecture before creating a pivot."
        )
    return True


def check_runtime_python_dependencies(*, full_container_runtime: bool, deps: Any) -> bool:
    """Check that runtime-managed Python libraries are importable.

    These dependencies live in the ADscan runtime Python environment rather
    than in host ``python3`` or isolated per-tool virtual environments, so they
    need a dedicated runtime check.
    """
    if not full_container_runtime:
        deps.print_info_verbose(
            "Skipping runtime Python dependency verification outside the ADscan container runtime."
        )
        return True

    deps.print_info("Checking runtime Python dependencies...")

    if getattr(sys, "frozen", False):
        deps.print_info_verbose(
            "PyInstaller runtime detected; verifying runtime Python dependencies inside the current bundled interpreter."
        )
        all_ok = True
        for import_name, display_name, usage in _RUNTIME_PYTHON_DEPENDENCIES:
            try:
                importlib.import_module(import_name)
            except Exception as exc:  # noqa: BLE001 - import diagnostics must not crash check
                deps.print_error(
                    f"Runtime Python dependency '{display_name}' is not importable ({usage})."
                )
                deps.print_instruction("Rebuild or update the ADscan runtime image.")
                deps.print_info_verbose(f"{display_name} import stderr: {exc}")
                all_ok = False
                continue

            distribution_name = _RUNTIME_PYTHON_DISTRIBUTION_NAMES.get(
                import_name, import_name
            )
            try:
                dependency_version = importlib.metadata.version(distribution_name)
            except importlib.metadata.PackageNotFoundError:
                dependency_version = ""
            version_suffix = f" ({dependency_version})" if dependency_version else ""
            deps.print_success(
                f"Runtime Python dependency '{display_name}' is importable{version_suffix}."
            )
        return all_ok

    runtime_python_candidates = [
        "/opt/adscan/venv/bin/python",
        shutil.which("python3"),
    ]
    if os.path.basename(sys.executable).startswith("python"):
        runtime_python_candidates.append(sys.executable)

    runtime_python = next(
        (
            candidate
            for candidate in runtime_python_candidates
            if candidate and os.path.exists(candidate)
        ),
        None,
    )
    if runtime_python is None:
        deps.print_error(
            "Could not determine a Python interpreter for runtime dependency verification."
        )
        deps.print_instruction("Rebuild or update the ADscan runtime image.")
        return False

    clean_env = deps.get_clean_env_for_compilation()
    runtime_python_dir = os.path.dirname(runtime_python)
    runtime_venv_dir = os.path.dirname(runtime_python_dir)
    if os.path.basename(runtime_python_dir) == "bin":
        clean_env["PATH"] = (
            f"{runtime_python_dir}{os.pathsep}{clean_env.get('PATH', os.environ.get('PATH', ''))}"
        )
        clean_env["VIRTUAL_ENV"] = runtime_venv_dir

    all_ok = True
    for import_name, display_name, usage in _RUNTIME_PYTHON_DEPENDENCIES:
        import_result = deps.run_command(
            [runtime_python, "-c", f"import {import_name}"],
            capture_output=True,
            check=False,
            env=clean_env,
        )
        if import_result.returncode != 0:
            deps.print_error(
                f"Runtime Python dependency '{display_name}' is not importable ({usage})."
            )
            deps.print_instruction("Rebuild or update the ADscan runtime image.")
            stderr = (import_result.stderr or "").strip()
            stdout = (import_result.stdout or "").strip()
            if stderr:
                deps.print_info_verbose(f"{display_name} import stderr: {stderr}")
            elif stdout:
                deps.print_info_verbose(f"{display_name} import stdout: {stdout}")
            all_ok = False
            continue

        dependency_version = deps.get_python_package_version(
            runtime_python,
            import_name,
            env=clean_env,
        )
        version_suffix = f" ({dependency_version})" if dependency_version else ""
        deps.print_success(
            f"Runtime Python dependency '{display_name}' is importable{version_suffix}."
        )
    return all_ok


# ─── DNS/Unbound Resolver Check ──────────────────────────────────────────────


@dataclass(frozen=True)
class DNSResolverCheckConfig:
    """Configuration for DNS resolver (Unbound) checks."""

    fix_mode: bool
    full_container_runtime: bool


@dataclass(frozen=True)
class DNSResolverCheckDeps:
    """Dependency bundle for DNS resolver checks."""

    # Low-level DNS/Unbound helpers from adscan.py
    is_unbound_listening_local: Callable[[], bool]
    get_port_53_listeners_text: Callable[[bool], str]
    extract_process_names_from_ss: Callable[[str], set[str]]
    stop_dns_resolver_service_for_unbound: Callable[..., None]
    start_unbound_without_systemd: Callable[[], bool]
    start_unbound_without_systemd_via_sudo: Callable[[], bool]

    # System/runtime helpers
    is_systemd_available: Callable[[], bool]
    build_effective_user_env_for_command: Callable[..., dict]
    sudo_validate: Callable[[], bool]
    sudo_prefix_args: Callable[[], list[str]]
    run_command: Callable[..., object]

    # Output
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_info_debug: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_instruction: Callable[[str], None]
    telemetry_capture_exception: Callable[[BaseException], None]


def check_dns_resolver(
    *, config: DNSResolverCheckConfig, deps: DNSResolverCheckDeps
) -> bool:
    """Check DNS resolver (Unbound) status and fix conflicts if requested.

    Returns:
        bool: True if Unbound is active and ready, False otherwise.
    """
    all_ok = True
    try:
        in_container = config.full_container_runtime
        systemd_available = deps.is_systemd_available()
        dnsmasq_active = None
        unbound_active = None
        if systemd_available:
            dnsmasq_active = deps.run_command(
                ["systemctl", "is-active", "dnsmasq"],
                check=False,
                capture_output=True,
                text=True,
            )
            unbound_active = deps.run_command(
                ["systemctl", "is-active", "unbound"],
                check=False,
                capture_output=True,
                text=True,
            )

        # When unprivileged, `ss -p` may hide process names. In `--fix`, we use `sudo -n`
        # (if available) so we can reliably detect which resolver holds port 53.
        sudo_ss = bool(config.fix_mode and os.geteuid() != 0 and shutil.which("sudo"))
        listeners = deps.get_port_53_listeners_text(use_sudo=sudo_ss)
        listener_processes = deps.extract_process_names_from_ss(listeners)
        dnsmasq_occupies_53 = "dnsmasq" in listener_processes

        if dnsmasq_occupies_53:
            deps.print_warning(
                "dnsmasq is active and is using port 53; this can prevent Unbound (ADscan DNS) from starting."
            )

            # In containers, service management is often unavailable and stopping a working
            # resolver can break outbound DNS (pip/git). Only auto-mitigate on host systems.
            if in_container:
                deps.print_info_verbose(
                    "Container environment detected; not stopping dnsmasq automatically."
                )
            elif config.fix_mode:
                # Only auto-mitigate when the user explicitly requested repairs.
                deps.stop_dns_resolver_service_for_unbound(
                    "dnsmasq",
                    systemd_available=systemd_available,
                    context="check --fix",
                )
            else:
                deps.print_info_verbose(
                    "Run `adscan check --fix` to stop dnsmasq automatically."
                )

            # Refresh status
            if systemd_available:
                unbound_active = deps.run_command(
                    ["systemctl", "is-active", "unbound"],
                    check=False,
                    capture_output=True,
                    text=True,
                )

        unbound_ok = False
        if systemd_available:
            unbound_ok = bool(unbound_active and unbound_active.returncode == 0)
        else:
            unbound_ok = deps.is_unbound_listening_local()

        if not unbound_ok:
            if in_container:
                deps.print_info(
                    "Unbound service is not active, but this is a container environment; "
                    "skipping automatic DNS service management."
                )
            elif config.fix_mode:
                deps.print_warning(
                    "Unbound service is not active (local DNS may not work)."
                )
                deps.print_info_verbose("Attempting to start Unbound...")

                # Proactively stop known conflicting DNS resolvers in --fix.
                if not in_container:
                    # Refresh listeners using sudo (if available) so we see process names.
                    listeners = deps.get_port_53_listeners_text(use_sudo=sudo_ss)
                    listener_processes = deps.extract_process_names_from_ss(listeners)
                    # Always stop dnsmasq when it's active: it is the main legacy conflict.
                    if dnsmasq_active and dnsmasq_active.returncode == 0:
                        deps.stop_dns_resolver_service_for_unbound(
                            "dnsmasq",
                            systemd_available=systemd_available,
                            context="unbound start preflight (dnsmasq active)",
                        )
                    # Some distros run systemd-resolved on 127.0.0.53:53; it can also block Unbound.
                    if "systemd-resolved" in listener_processes:
                        deps.stop_dns_resolver_service_for_unbound(
                            "systemd-resolved",
                            systemd_available=systemd_available,
                            context="unbound start preflight",
                        )

                    # For additional resolvers, warn (we avoid blindly stopping unknown services).
                    other_procs = sorted(
                        p
                        for p in listener_processes
                        if p not in {"dnsmasq", "unbound", "systemd-resolved"}
                    )
                    if other_procs:
                        deps.print_warning(
                            "Another DNS resolver appears to be listening on port 53; "
                            "this can prevent Unbound from starting."
                        )
                        deps.print_info_verbose(
                            f"[dns] Port 53 listeners: {', '.join(other_procs)}"
                        )

                if systemd_available:
                    unbound_env = deps.build_effective_user_env_for_command(
                        ["systemctl", "start", "unbound"], shell=False
                    )
                    if os.geteuid() != 0 and not deps.sudo_validate():
                        deps.print_warning(
                            "Cannot start Unbound automatically without sudo privileges."
                        )
                    else:
                        deps.run_command(
                            (
                                deps.sudo_prefix_args()
                                + ["systemctl", "enable", "unbound"]
                            )
                            if os.geteuid() != 0
                            else ["systemctl", "enable", "unbound"],
                            check=False,
                            capture_output=True,
                            text=True,
                            env=unbound_env if os.geteuid() != 0 else None,
                        )
                        deps.run_command(
                            (
                                deps.sudo_prefix_args()
                                + ["systemctl", "start", "unbound"]
                            )
                            if os.geteuid() != 0
                            else ["systemctl", "start", "unbound"],
                            check=False,
                            capture_output=True,
                            text=True,
                            env=unbound_env if os.geteuid() != 0 else None,
                        )
                    unbound_active = deps.run_command(
                        ["systemctl", "is-active", "unbound"],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    unbound_ok = bool(unbound_active and unbound_active.returncode == 0)
                else:
                    unbound_ok = deps.start_unbound_without_systemd()
                    if not unbound_ok:
                        unbound_ok = deps.start_unbound_without_systemd_via_sudo()

                if unbound_ok:
                    deps.print_success("Unbound service is active and ready")
                else:
                    deps.print_warning(
                        "Unbound service could not be started automatically."
                    )
                    if listeners:
                        deps.print_info_verbose(
                            f"[dns] Port 53 listeners after start attempt:\n{listeners}"
                        )
                    if systemd_available:
                        deps.print_instruction("Try: sudo systemctl start unbound")
                    else:
                        deps.print_instruction(
                            "Try: sudo unbound -d -p -c /etc/unbound/unbound.conf"
                        )
                        deps.print_info(
                            "If this is a container, run it as root or grant CAP_NET_BIND_SERVICE "
                            "so Unbound can bind to port 53."
                        )
                    all_ok = False
            else:
                deps.print_warning(
                    "Unbound service is not active (local DNS may not work)."
                )
                all_ok = False
    except Exception as e:
        deps.telemetry_capture_exception(e)
        deps.print_info_debug(
            "[dns] Could not fully verify local DNS resolver services."
        )

    return all_ok


# ─── Docker/Compose Check (BloodHound CE) ────────────────────────────────────


@dataclass(frozen=True)
class DockerComposeCheckConfig:
    """Configuration for Docker/Compose checks (BloodHound CE)."""

    bh_mode: str  # "ce" or other
    fix_mode: bool
    full_container_runtime: bool
    bloodhound_ce_dir: str


@dataclass(frozen=True)
class DockerComposeCheckDeps:
    """Dependency bundle for Docker/Compose checks."""

    # Docker/BloodHound helpers
    is_docker_official_installed: Callable[[], tuple[bool, str]]
    is_docker_compose_plugin_available: Callable[[], tuple[bool, str]]
    check_bloodhound_ce_running: Callable[[], bool]
    start_bloodhound_ce: Callable[[], bool]
    get_bloodhound_cli_executable_path: Callable[[], str | None]

    # System helpers
    is_docker_env: Callable[[], bool]
    expand_effective_user_path: Callable[[str], str]
    path_exists: Callable[[str], bool]
    path_access: Callable[[str, int], bool]

    # Output
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_success: Callable[[str], None]
    print_success_verbose: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    print_panel: Callable[..., None]
    print_exception: Callable[..., None]
    telemetry_capture_exception: Callable[[BaseException], None]


def check_docker_compose(
    *, config: DockerComposeCheckConfig, deps: DockerComposeCheckDeps
) -> bool:
    """Check Docker/Compose for BloodHound CE and fix if needed.

    Returns:
        bool: True if all checks pass, False otherwise.
    """
    # Only check if BloodHound CE mode is enabled
    if config.bh_mode != "ce":
        return True

    all_ok = True
    deps.print_info("Checking Docker and Docker Compose for BloodHound CE...")
    in_docker_container = deps.is_docker_env()

    if in_docker_container:
        deps.print_warning(
            "Running inside a Docker container - BloodHound CE checks will be informational only"
        )
        deps.print_info(
            "Docker-in-Docker (DinD) is not supported in most CI/CD environments"
        )

    # Check official Docker Engine
    docker_installed, docker_version = deps.is_docker_official_installed()
    if docker_installed:
        deps.print_success(f"Official Docker Engine found: {docker_version}")
    else:
        if in_docker_container:
            deps.print_warning(
                f"Docker not found (expected in container environment): {docker_version}"
            )
        else:
            deps.print_error(
                "Docker not found or not official. BloodHound CE requires official Docker Engine."
            )
            deps.print_instruction("Run: adscan install --only bloodhound")
            all_ok = False

    # Check Docker Compose plugin
    compose_available, compose_version = deps.is_docker_compose_plugin_available()
    if compose_available:
        deps.print_success(f"Docker Compose plugin found: {compose_version}")
    else:
        if in_docker_container:
            deps.print_warning(
                f"Docker Compose not found (expected in container environment): {compose_version}"
            )
        else:
            deps.print_error(
                "Docker Compose plugin not found. BloodHound CE requires Docker Compose plugin."
            )
            deps.print_instruction("Run: adscan install --only bloodhound")
            all_ok = False

    # Check BloodHound CE configuration (managed path first, legacy fallback)
    managed_compose_path = deps.expand_effective_user_path(
        "~/.adscan/bloodhound/bloodhound-ce/docker-compose.yml"
    )
    legacy_compose_path = deps.expand_effective_user_path(
        "~/.config/bloodhound/docker-compose.yml"
    )
    if deps.path_exists(managed_compose_path):
        deps.print_success(
            f"BloodHound CE managed configuration found: {managed_compose_path}"
        )
    elif deps.path_exists(legacy_compose_path):
        deps.print_warning(
            f"BloodHound CE legacy configuration found: {legacy_compose_path}"
        )
        deps.print_info(
            "ADscan now uses the managed isolated BloodHound CE stack under ~/.adscan."
        )
    else:
        deps.print_warning(
            "BloodHound CE configuration not found in managed or legacy locations"
        )
        deps.print_info("This will be created automatically when needed.")

    # Check bloodhound-cli installation
    deps.print_info("Checking bloodhound-cli installation...")
    bloodhound_cli_path = os.path.join(config.bloodhound_ce_dir, "bloodhound-ce-cli")
    if deps.path_exists(bloodhound_cli_path) and deps.path_access(
        bloodhound_cli_path, os.X_OK
    ):
        deps.print_success(f"bloodhound-cli found at: {bloodhound_cli_path}")
    else:
        deps.print_warning("bloodhound-cli not found or not executable")
        if not in_docker_container:
            if config.fix_mode:
                deps.print_info("Installing bloodhound-cli (--fix)...")
                try:
                    # Reuse the same resolution logic used during installation:
                    # prefer venv-installed bloodhound-cli, then bundled CLI in
                    # BLOODHOUND_CE_DIR, and finally PATH. If it is still not
                    # found, instruct the user to install it manually.
                    cli_path = deps.get_bloodhound_cli_executable_path()
                    if not cli_path:
                        deps.print_warning(
                            "bloodhound-cli executable not found; install it via "
                            "`pip install bloodhound-cli` or rerun `adscan install`."
                        )
                    if deps.path_exists(bloodhound_cli_path) and deps.path_access(
                        bloodhound_cli_path, os.X_OK
                    ):
                        deps.print_success("bloodhound-cli installed successfully")
                    else:
                        deps.print_error("Failed to install bloodhound-cli")
                        all_ok = False
                except Exception as e:
                    deps.telemetry_capture_exception(e)
                    deps.print_error("Failed to install bloodhound-cli.")
                    deps.print_exception(show_locals=False, exception=e)
                    all_ok = False
            else:
                deps.print_info(
                    "Run `adscan check --fix` to install bloodhound-cli automatically."
                )
                all_ok = False
        else:
            deps.print_info(
                "Skipping bloodhound-cli installation (running in container)"
            )

    # Check BloodHound CE containers status
    deps.print_info("Checking BloodHound CE containers status...")
    if deps.check_bloodhound_ce_running():
        deps.print_success("All 3 BloodHound CE containers are running")
    else:
        if in_docker_container:
            deps.print_warning(
                "BloodHound CE containers are not running (expected in container environment)"
            )
            deps.print_info(
                "BloodHound CE requires Docker-in-Docker which is not available in this environment"
            )
        else:
            deps.print_warning("BloodHound CE containers are not running")
            try:
                if config.fix_mode:
                    if deps.start_bloodhound_ce():
                        deps.print_success_verbose(
                            "BloodHound CE containers started successfully"
                        )
                    else:
                        deps.print_error("Failed to start BloodHound CE containers")
                        deps.print_info("Try running: adscan install --only bloodhound")
                        all_ok = False
                else:
                    deps.print_info(
                        "Run `adscan check --fix` to attempt starting BloodHound CE containers automatically."
                    )
                    all_ok = False
            except Exception as e:
                deps.telemetry_capture_exception(e)
                deps.print_error("Error starting BloodHound CE containers.")
                deps.print_exception(show_locals=False, exception=e)
                deps.print_info("Try running: adscan install --only bloodhound")
                all_ok = False

    return all_ok


# ─── Go Toolchain and htb-cli Check ────────────────────────────────────────


@dataclass(frozen=True)
class GoToolsCheckConfig:
    """Configuration for Go toolchain checks."""

    full_container_runtime: bool
    fix_mode: bool
    session_env: str


@dataclass(frozen=True)
class GoToolsCheckDeps:
    """Dependency bundle for Go toolchain checks."""

    # Go helpers
    is_go_available: Callable[[os._Environ[str]], tuple[bool, str]]
    configure_go_official_path: Callable[[], None]
    configure_go_path: Callable[[], None]
    is_htb_cli_available: Callable[[], tuple[bool, str]]

    # System helpers
    os_environ: os._Environ[str]
    subprocess_run: Callable[..., Any]

    # Output
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]


def check_go_tools(*, config: GoToolsCheckConfig, deps: GoToolsCheckDeps) -> bool:
    """Check Go toolchain and htb-cli (CI-only) status."""

    all_ok = True

    if config.full_container_runtime:
        deps.print_info(
            "Skipping Go toolchain and htb-cli verification (running in container)."
        )
        return all_ok

    deps.print_info("Checking Go toolchain...")

    # Configure PATH only when explicitly requested
    if config.fix_mode:
        deps.configure_go_official_path()
        if config.session_env == "ci":
            deps.configure_go_path()

    go_available, go_version = deps.is_go_available(deps.os_environ)
    if go_available:
        deps.print_success(f"Go found: {go_version}")

        go_path_check = deps.subprocess_run(
            ["which", "go"], capture_output=True, text=True, check=False
        )
        if go_path_check.returncode == 0:
            go_binary_path = go_path_check.stdout.strip()
            if "/usr/local/go/bin/go" in go_binary_path:
                deps.print_info(
                    "Go is installed from official golang.org source (latest version)"
                )
            else:
                deps.print_warning(
                    "Go appears to be installed via system package manager (apt)"
                )
                deps.print_info(
                    "   Consider installing from official source for latest version:"
                )
                deps.print_info(
                    "   Run: adscan install (will install Go from golang.org)"
                )
    else:
        deps.print_warning("Go not found")
        deps.print_info(
            "   Install with: adscan install (will install Go from official golang.org source)"
        )
        deps.print_info(
            "   Or manually: curl -L https://go.dev/dl/go1.23.4.linux-amd64.tar.gz | sudo tar -C /usr/local -xzf -"
        )
        all_ok = False

    if config.session_env != "ci":
        deps.print_info_verbose(
            f"Skipping htb-cli verification in environment '{config.session_env}' (CI-only)."
        )
        return all_ok

    deps.print_info("Checking htb-cli installation (CI-only)...")
    htb_cli_available, htb_cli_version = deps.is_htb_cli_available()
    if htb_cli_available:
        deps.print_success(f"htb-cli found: {htb_cli_version}")
    else:
        deps.print_warning("htb-cli not found")
        deps.print_info(
            "htb-cli is only required in CI environments (for HTB validations)."
        )
        all_ok = False

    return all_ok


# ─── Rust Tools Check (rusthound-ce) ──────────────────────────────────────


@dataclass(frozen=True)
class RustToolsCheckConfig:
    """Configuration for Rust tools checks."""

    full_container_runtime: bool
    fix_mode: bool


@dataclass(frozen=True)
class RustToolsCheckDeps:
    """Dependency bundle for Rust tools checks."""

    # Rust/rusthound helpers
    is_rustup_available: Callable[[os._Environ[str]], tuple[bool, str]]
    get_rusthound_verification_status: Callable[..., dict]
    configure_cargo_path: Callable[[], None]

    # System helpers
    shutil_which: Callable[[str], str | None]
    os_environ: os._Environ[str]

    # Output
    print_info: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]


def check_rust_tools(*, config: RustToolsCheckConfig, deps: RustToolsCheckDeps) -> bool:
    """Check Rust toolchain and rusthound-ce installation.

    Returns:
        bool: True if all checks pass, False otherwise.
    """
    all_ok = True

    if config.full_container_runtime:
        deps.print_info("Checking RustHound-CE (container image)...")
        rusthound_path = deps.shutil_which("rusthound-ce")
        if rusthound_path:
            deps.print_success(f"RustHound-CE found: {rusthound_path}")
        else:
            deps.print_error("RustHound-CE not found in this container image.")
            all_ok = False
    else:
        deps.print_info("Checking Rust toolchain and rusthound-ce...")

        # Configure PATH for consistent verification (same as install)
        if config.fix_mode:
            deps.configure_cargo_path()

        # Check rustup availability first (recommended installation method)
        rustup_available, rustup_version = deps.is_rustup_available(deps.os_environ)
        if rustup_available:
            deps.print_success(f"rustup found: {rustup_version}")
            deps.print_info("Using official Rust installer (recommended)")
        else:
            deps.print_warning("rustup not found")
            deps.print_info("rustup is the official Rust installer and is recommended")
            deps.print_info(
                "   Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
            )
            deps.print_info(
                "   Or run: adscan install (will install rustup automatically)"
            )

        # Use the unified verification function with current environment
        rusthound_status = deps.get_rusthound_verification_status(env=deps.os_environ)
        if (
            not isinstance(rusthound_status, dict)
            or "verification_results" not in rusthound_status
        ):
            deps.print_error("Error getting rusthound verification status")
            all_ok = False
            return all_ok
        verification_results = rusthound_status["verification_results"]
        messages = rusthound_status["messages"]

        # Check cargo availability
        if verification_results["cargo_available"]:
            deps.print_success(messages["cargo"])
            # If cargo is available but rustup is not, it might be from apt (old version)
            if not rustup_available:
                deps.print_warning(
                    "cargo appears to be installed via system package manager (apt)"
                )
                deps.print_info(
                    "   This may cause compatibility issues with newer Rust crates"
                )
                deps.print_info(
                    "   Consider migrating to rustup: adscan install --only rusthound"
                )
        else:
            deps.print_warning(messages["cargo"])
            deps.print_info(
                f"Cargo check failed: {verification_results['cargo_version']}"
            )
            # Print cargo-related recommendations
            for recommendation in messages["recommendations"]:
                if (
                    "cargo" in recommendation.lower()
                    or "rustup" in recommendation.lower()
                ):
                    deps.print_info(recommendation)
            all_ok = False

        # Check rusthound-ce installation
        if verification_results["rusthound_installed"]:
            deps.print_success(messages["rusthound_installed"])
        else:
            deps.print_warning(messages["rusthound_installed"])
            # Show relevant recommendations for rusthound installation
            for recommendation in messages["recommendations"]:
                if "rusthound" in recommendation.lower() and (
                    "install" in recommendation or "cargo install" in recommendation
                ):
                    deps.print_info(recommendation)
            all_ok = False

        # Check cargo bin in PATH
        if verification_results["cargo_bin_in_path"]:
            deps.print_success(messages["cargo_bin_path"])
        else:
            deps.print_warning(messages["cargo_bin_path"])
            # Print relevant recommendations for cargo bin PATH
            for recommendation in messages["recommendations"]:
                if (
                    "export PATH" in recommendation
                    or "install --only rusthound" in recommendation
                ):
                    deps.print_info(recommendation)

        # Check rusthound-ce accessibility
        if verification_results["rusthound_accessible"]:
            deps.print_success(messages["rusthound_accessible"])
        else:
            deps.print_warning(messages["rusthound_accessible"])
            # Print relevant recommendations for rusthound accessibility
            for recommendation in messages["recommendations"]:
                if (
                    "restarting terminal" in recommendation
                    or "install --only rusthound" in recommendation
                    or "configure PATH automatically" in recommendation
                ):
                    deps.print_info(recommendation)

        # Overall RustHound-CE status
        if verification_results["overall_status"]:
            deps.print_success(messages["overall"])
        else:
            deps.print_warning(messages["overall"])
            # Print general installation recommendations
            for recommendation in messages["recommendations"]:
                if (
                    "install --only rusthound" in recommendation
                    and "fix" in recommendation
                ):
                    deps.print_info(recommendation)
                    break
            all_ok = False

    return all_ok


# ─── Pyenv Check ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PyenvCheckConfig:
    """Configuration for pyenv checks."""

    full_container_runtime: bool
    fix_mode: bool
    python_version: str
    venv_path: str


@dataclass(frozen=True)
class PyenvCheckDeps:
    """Dependency bundle for pyenv checks."""

    check_and_ensure_pyenv_status: Callable[..., Dict[str, Any]]
    install_pyenv_python_and_venv: Callable[..., tuple[bool, List[str], str]]
    expand_effective_user_path: Callable[[str], str]
    regenerate_pyenv_shims: Callable[[], bool]
    fix_pyenv_shims_permissions: Callable[[], bool]
    mark_sensitive: Callable[..., Any]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    print_panel: Callable[..., None]
    print_exception: Callable[..., None]
    telemetry_capture_exception: Callable[[BaseException], None]


def check_pyenv_status(*, config: PyenvCheckConfig, deps: PyenvCheckDeps) -> bool:
    """Check pyenv and Python version management status.

    Returns:
        bool: True if pyenv checks pass, False otherwise.
    """
    if config.full_container_runtime:
        deps.print_info_verbose("Skipping pyenv verification (running in container).")
        return True

    deps.print_info("Checking pyenv and Python version management...")

    try:
        pyenv_status = deps.check_and_ensure_pyenv_status(
            python_version=config.python_version,
            auto_configure=config.fix_mode,
        )

        if pyenv_status.get("installed") and pyenv_status.get("accessible"):
            deps.print_success("pyenv is installed and accessible")
            if pyenv_status.get("python_installed"):
                deps.print_success(
                    f"Python {config.python_version} is installed via pyenv"
                )
            else:
                deps.print_warning(
                    f"Python {config.python_version} is not installed via pyenv"
                )
                if config.fix_mode:
                    deps.print_info(
                        f"Installing Python {config.python_version} via pyenv (--fix)..."
                    )
                    ok, _, _ = deps.install_pyenv_python_and_venv(
                        python_version=config.python_version,
                        venv_path=config.venv_path,
                    )
                    if ok:
                        deps.print_success(
                            f"Python {config.python_version} installed successfully"
                        )
                    else:
                        deps.print_error(
                            f"Failed to install Python {config.python_version}"
                        )
                        return False
                else:
                    return False
        else:
            deps.print_warning("pyenv is not installed or not accessible")
            if config.fix_mode:
                deps.print_info("Installing pyenv (--fix)...")
                deps.print_instruction(
                    "Please install pyenv manually: curl https://pyenv.run | bash"
                )
                return False
            else:
                deps.print_instruction("Install pyenv: curl https://pyenv.run | bash")
                return False

        if pyenv_status.get("shims_need_rehash"):
            if config.fix_mode:
                deps.print_info("Regenerating pyenv shims (--fix)...")
                if deps.regenerate_pyenv_shims():
                    deps.print_success("pyenv shims regenerated successfully")
                else:
                    deps.print_warning("Failed to regenerate pyenv shims")
            else:
                deps.print_warning("pyenv shims need regeneration")

        return True

    except Exception as exc:
        deps.telemetry_capture_exception(exc)
        deps.print_error("Error checking pyenv status")
        deps.print_exception(show_locals=False, exception=exc)
        return False


@dataclass(frozen=True)
class CheckConfig:
    """Configuration for the main check process.

    Attributes:
        args: Optional argparse.Namespace with check arguments.
        adscan_base_dir: Base directory for ADscan installation.
        tools_install_dir: Directory for external tools.
        wordlists_install_dir: Directory for wordlists.
        tool_venvs_base_dir: Base directory for tool virtual environments.
        venv_path: Path to the main virtual environment.
        bloodhound_ce_dir: Path to BloodHound CE directory.
        core_requirements: Core Python requirements.
        pip_tools_config: Configuration for pip tools.
        external_tools_config: Configuration for external tools.
        system_packages_config: Configuration for system packages.
        python_version: Python version to check (default: "3.12.3").
    """

    args: Any | None
    adscan_base_dir: str
    tools_install_dir: str
    wordlists_install_dir: str
    tool_venvs_base_dir: str
    venv_path: str
    bloodhound_ce_dir: str
    core_requirements: List[str]
    pip_tools_config: Dict[str, Any]
    external_tools_config: Dict[str, Any]
    system_packages_config: Dict[str, str]
    python_version: str


@dataclass(frozen=True)
class CheckDeps:
    """Dependency bundle for the main check flow."""

    # Environment detection
    is_full_adscan_container_runtime: Callable[[], bool]
    determine_session_environment: Callable[[], str]
    get_bloodhound_mode: Callable[[], str]

    # Directory operations
    ensure_dir_writable: Callable[..., bool]

    # Check helpers (already in check.py)
    check_virtual_environment: Callable[..., tuple[bool, bool]]
    check_core_dependencies: Callable[..., bool]
    check_external_tools: Callable[..., bool]
    check_system_packages: Callable[..., tuple[bool, List[str]]]
    check_dns_resolver: Callable[..., bool]
    check_external_binary_tools: Callable[..., tuple[bool, List[str]]]
    check_docker_compose: Callable[..., bool]
    check_rust_tools: Callable[..., bool]
    check_go_toolchain: Callable[..., bool]
    check_pyenv_status: Callable[..., bool]

    # Helper functions
    is_libreoffice_available: Callable[[], tuple[bool, str]]
    print_check_summary: Callable[[bool], None]

    # Wordlist service
    WordlistService: type

    # Command execution
    run_command: Callable[..., object]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    parse_requirement_spec: Callable[[str], Any]
    get_python_package_version: Callable[..., str | None]
    assess_version_compliance: Callable[..., bool]
    get_installed_vcs_reference: Callable[..., str | None]
    get_installed_vcs_reference_by_url: Callable[..., str | None]
    normalize_vcs_repo_url: Callable[[str], str]
    vcs_reference_matches: Callable[..., bool]
    build_venv_exec_env: Callable[..., Dict[str, str]]
    check_executable_help_works: Callable[..., bool]
    fix_isolated_python_tool_venv: Callable[..., bool]
    diagnose_manspider_help_failure: Callable[..., None]
    ensure_isolated_tool_extra_specs_installed: Callable[..., bool]
    verify_system_packages: Callable[..., tuple[bool, List[str]]]
    apply_effective_user_home_to_env: Callable[..., Dict[str, str]]
    sudo_validate: Callable[..., bool]
    is_unbound_listening_local: Callable[[], bool]
    get_port_53_listeners_text: Callable[[], str]
    extract_process_names_from_ss: Callable[[str], List[str]]
    stop_dns_resolver_service_for_unbound: Callable[[], bool]
    start_unbound_without_systemd: Callable[[], bool]
    start_unbound_without_systemd_via_sudo: Callable[[], bool]
    is_systemd_available: Callable[[], bool]
    build_effective_user_env_for_command: Callable[..., Dict[str, str]]
    sudo_prefix_args: Callable[..., List[str]]
    expand_effective_user_path: Callable[[str], str]
    preflight_install_dns: Callable[[], bool]
    setup_external_tool: Callable[..., bool]
    is_docker_official_installed: Callable[[], tuple[bool, str]]
    is_docker_compose_plugin_available: Callable[[], tuple[bool, str]]
    check_bloodhound_ce_running: Callable[[], bool]
    start_bloodhound_ce: Callable[[], bool]
    get_bloodhound_cli_executable_path: Callable[[], str]
    is_docker_env: Callable[[], bool]
    is_rustup_available: Callable[[], tuple[bool, str]]
    get_rusthound_verification_status: Callable[[], Dict[str, Any]]
    configure_cargo_path: Callable[[], bool]
    configure_go_official_path: Callable[[], bool]
    configure_go_path: Callable[[], bool]
    is_go_available: Callable[[], tuple[bool, str]]
    is_go_bin_in_path: Callable[[], tuple[bool, str]]
    is_htb_cli_installed: Callable[[], tuple[bool, str]]
    is_htb_cli_accessible: Callable[[], tuple[bool, str]]
    check_and_ensure_pyenv_status: Callable[..., Dict[str, Any]]
    install_pyenv_python_and_venv: Callable[..., tuple[bool, List[str], str]]
    regenerate_pyenv_shims: Callable[[], bool]
    fix_pyenv_shims_permissions: Callable[[], bool]

    # Telemetry
    telemetry_capture: Callable[[str, Dict[str, Any]], None]
    telemetry_capture_exception: Callable[[BaseException], None]

    # Output functions
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_info_debug: Callable[[str], None]
    print_success: Callable[[str], None]
    print_success_verbose: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    print_panel: Callable[..., None]
    print_exception: Callable[..., None]

    # Interactive prompts
    confirm_ask: Callable[..., bool]
    track_docs_link_shown: Callable[[str, str], None]

    # Standard library
    os_getenv: Callable[[str, str | None], str | None]
    os_path_exists: Callable[[str], bool]
    os_path_access: Callable[[str, int], bool]
    sys_stdin_isatty: Callable[[], bool]
    argparse_namespace: type
    shutil_which: Callable[[str], str | None]
    os_environ: Dict[str, str]
    subprocess_run: Callable[..., Any]

    # Mark sensitive
    mark_sensitive: Callable[..., Any]

    # Global state setter (for _LAST_CHECK_SESSION_EXTRA)
    set_last_check_session_extra: Callable[[Dict[str, Any] | None], None]

    # Recursive check (for interactive fix prompt)
    handle_check: Callable[[Any], bool]


def run_check(
    *,
    config: CheckConfig,
    deps: CheckDeps,
) -> bool:
    """Main check orchestrator.

    This function orchestrates the complete check process for ADscan,
    including virtual environment, dependencies, tools, wordlists, Docker,
    Rust, Go, and pyenv checks.

    All I/O, subprocess calls, and telemetry are injected via ``deps`` to keep
    this function testable and to avoid circular imports with ``adscan.py``.

    Returns:
        True if all checks passed, False otherwise.
    """
    deps.print_info("Checking adscan installation status...")
    deps.set_last_check_session_extra(None)

    all_ok = True
    full_container_runtime = deps.is_full_adscan_container_runtime()
    session_env = deps.determine_session_environment()
    fix_mode = (
        bool(getattr(config.args, "fix", False)) if config.args is not None else False
    )
    fix_trigger = (
        getattr(config.args, "fix_trigger", None)
        if config.args is not None and fix_mode
        else None
    )
    pre_fix_failed = (
        bool(getattr(config.args, "pre_fix_failed", False))
        if config.args is not None and fix_mode
        else False
    )
    missing_tools: List[str] = []
    tool_version_issues: List[str] = []
    missing_system_packages_count = 0
    dnsmasq_occupies_53_for_check: bool | None = None
    unbound_ok_for_check: bool | None = None

    if full_container_runtime:
        deps.set_last_check_session_extra({"mode": "container"})
        if not _check_container_runtime_version_alignment(deps):
            all_ok = False

    _emit_local_update_recency_guidance(deps)

    if fix_mode:
        deps.telemetry_capture(
            "check_fix_started",
            properties={"trigger": fix_trigger or "flag"},
        )
        # Older versions (or legacy sudo aliases) could create root-owned ~/.adscan,
        # which then breaks `--fix` because we can't create venvs/tools directories.
        deps.ensure_dir_writable(
            config.adscan_base_dir,
            description="ADscan base",
            fix=True,
            recursive=True,
        )
        deps.ensure_dir_writable(
            config.tools_install_dir,
            description="ADscan tools",
            fix=True,
            recursive=True,
        )
        deps.ensure_dir_writable(
            config.wordlists_install_dir,
            description="ADscan wordlists",
            fix=True,
            recursive=True,
        )

    # 1. Check Virtual Environment (host/legacy installer only)
    #
    # In the FULL Docker runtime image, ADscan runs as a self-contained binary with
    # pre-provisioned tool envs under `/opt/adscan`. A host-based venv is not required.
    from adscan_internal.cli.check import (
        VirtualEnvCheckConfig,
        VirtualEnvCheckDeps,
    )

    adscan_venv_ok, all_ok = deps.check_virtual_environment(
        config=VirtualEnvCheckConfig(
            adscan_base_dir=config.adscan_base_dir,
            venv_path=config.venv_path,
            full_container_runtime=full_container_runtime,
            fix_mode=fix_mode,
        ),
        deps=VirtualEnvCheckDeps(
            ensure_dir_writable=deps.ensure_dir_writable,
            install_pyenv_python_and_venv=deps.install_pyenv_python_and_venv,
            run_command=deps.run_command,
            path_exists=deps.os_path_exists,
            print_success=deps.print_success,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
            print_instruction=deps.print_instruction,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            telemetry_capture_exception=deps.telemetry_capture_exception,
            print_exception=deps.print_exception,
        ),
    )

    # 2. Check Core Dependencies in System Python (delegated helper)
    from adscan_internal.cli.check import (
        CoreDepsCheckConfig,
        CoreDepsCheckDeps,
    )

    core_ok = deps.check_core_dependencies(
        config=CoreDepsCheckConfig(core_requirements=config.core_requirements),
        deps=CoreDepsCheckDeps(
            run_command=deps.run_command,
            get_clean_env_for_compilation=deps.get_clean_env_for_compilation,
            parse_requirement_spec=deps.parse_requirement_spec,
            get_python_package_version=lambda py, pkg: deps.get_python_package_version(
                py, pkg, env=deps.get_clean_env_for_compilation()
            ),
            assess_version_compliance=deps.assess_version_compliance,
            get_installed_vcs_reference=lambda py,
            pkg: deps.get_installed_vcs_reference(
                py, pkg, env=deps.get_clean_env_for_compilation()
            ),
            get_installed_vcs_reference_by_url=lambda py,
            url: deps.get_installed_vcs_reference_by_url(  # noqa: E501
                py, url, env=deps.get_clean_env_for_compilation()
            ),
            normalize_vcs_repo_url=deps.normalize_vcs_repo_url,
            vcs_reference_matches=deps.vcs_reference_matches,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_success=deps.print_success,
            print_success_verbose=deps.print_success_verbose,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
            print_instruction=deps.print_instruction,
            telemetry_capture_exception=deps.telemetry_capture_exception,
        ),
    )
    all_ok = all_ok and core_ok

    # 3. Check External Python Tool Dependencies in their isolated venvs (delegated)
    from adscan_internal.cli.check import (
        ExternalToolsCheckConfig,
        ExternalToolsCheckDeps,
    )

    if adscan_venv_ok:  # Only if main venv exists (or we're in FULL container runtime)
        tools_ok = deps.check_external_tools(
            config=ExternalToolsCheckConfig(
                pip_tools_config=config.pip_tools_config,
                tool_venvs_base_dir=config.tool_venvs_base_dir,
                fix_mode=fix_mode,
            ),
            deps=ExternalToolsCheckDeps(
                run_command=deps.run_command,
                parse_requirement_spec=deps.parse_requirement_spec,
                build_venv_exec_env=deps.build_venv_exec_env,
                check_executable_help_works=deps.check_executable_help_works,
                fix_isolated_python_tool_venv=deps.fix_isolated_python_tool_venv,
                diagnose_manspider_help_failure=deps.diagnose_manspider_help_failure,
                ensure_isolated_tool_extra_specs_installed=deps.ensure_isolated_tool_extra_specs_installed,
                get_clean_env_for_compilation=deps.get_clean_env_for_compilation,
                get_python_package_version=deps.get_python_package_version,
                assess_version_compliance=deps.assess_version_compliance,
                get_installed_vcs_reference=deps.get_installed_vcs_reference,
                get_installed_vcs_reference_by_url=deps.get_installed_vcs_reference_by_url,
                normalize_vcs_repo_url=deps.normalize_vcs_repo_url,
                vcs_reference_matches=deps.vcs_reference_matches,
                print_info=deps.print_info,
                print_info_verbose=deps.print_info_verbose,
                print_success=deps.print_success,
                print_success_verbose=deps.print_success_verbose,
                print_warning=deps.print_warning,
                print_error=deps.print_error,
                print_instruction=deps.print_instruction,
                telemetry_capture_exception=deps.telemetry_capture_exception,
            ),
        )
        all_ok = all_ok and tools_ok
    else:
        deps.print_info_verbose(
            "Skipping external Python tool verification because the main environment is not ready."
        )

    # 3b. Check runtime-managed Python dependencies.
    runtime_python_deps_ok = check_runtime_python_dependencies(
        full_container_runtime=full_container_runtime,
        deps=deps,
    )
    if not runtime_python_deps_ok:
        all_ok = False

    # 4. Check System Packages (delegated)
    from adscan_internal.cli.check import (
        SystemPackagesCheckConfig,
        SystemPackagesCheckDeps,
    )

    bh_mode = deps.get_bloodhound_mode()
    system_packages_to_verify = config.system_packages_config.copy()
    if bh_mode == "ce":
        system_packages_to_verify.pop("neo4j", None)

    sp_ok, sp_missing = deps.check_system_packages(
        config=SystemPackagesCheckConfig(
            system_packages_to_verify=system_packages_to_verify,
            fix_mode=fix_mode,
            full_container_runtime=full_container_runtime,
        ),
        deps=SystemPackagesCheckDeps(
            verify_system_packages=deps.verify_system_packages,
            run_command=deps.run_command,
            get_clean_env_for_compilation=deps.get_clean_env_for_compilation,
            apply_effective_user_home_to_env=deps.apply_effective_user_home_to_env,
            sudo_validate=deps.sudo_validate,
            print_info=deps.print_info,
            print_info_debug=deps.print_info_debug,
            print_success=deps.print_success,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
            print_instruction=deps.print_instruction,
            telemetry_capture_exception=deps.telemetry_capture_exception,
            print_exception=deps.print_exception,
        ),
    )
    if not sp_ok:
        all_ok = False
        missing_system_packages_count = len(sp_missing)

    # DNS resolver conflicts (dnsmasq vs Unbound) - delegated helper
    from adscan_internal.cli.check import (
        DNSResolverCheckConfig,
        DNSResolverCheckDeps,
    )

    dns_ok = deps.check_dns_resolver(
        config=DNSResolverCheckConfig(
            fix_mode=fix_mode,
            full_container_runtime=full_container_runtime,
        ),
        deps=DNSResolverCheckDeps(
            is_unbound_listening_local=deps.is_unbound_listening_local,
            get_port_53_listeners_text=deps.get_port_53_listeners_text,
            extract_process_names_from_ss=deps.extract_process_names_from_ss,
            stop_dns_resolver_service_for_unbound=deps.stop_dns_resolver_service_for_unbound,
            start_unbound_without_systemd=deps.start_unbound_without_systemd,
            start_unbound_without_systemd_via_sudo=deps.start_unbound_without_systemd_via_sudo,
            is_systemd_available=deps.is_systemd_available,
            build_effective_user_env_for_command=deps.build_effective_user_env_for_command,
            sudo_validate=deps.sudo_validate,
            sudo_prefix_args=deps.sudo_prefix_args,
            run_command=deps.run_command,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_info_debug=deps.print_info_debug,
            print_success=deps.print_success,
            print_warning=deps.print_warning,
            print_instruction=deps.print_instruction,
            telemetry_capture_exception=deps.telemetry_capture_exception,
        ),
    )
    if not dns_ok:
        all_ok = False

    # Check libreoffice specifically for PDF conversion capability
    deps.print_info("Checking libreoffice for PDF conversion...")
    libreoffice_available, libreoffice_info = deps.is_libreoffice_available()
    if libreoffice_available:
        deps.print_success(f"libreoffice is available: {libreoffice_info}")
    else:
        deps.print_warning(f"libreoffice is not available: {libreoffice_info}")
        deps.print_info("libreoffice is required for PDF report generation")
        deps.print_instruction("Install with: sudo apt-get install -y libreoffice")
        # Don't set all_ok = False here as libreoffice is optional (only needed for PDF reports)

    # 5. Check External Tools (delegated for non-Python tools)
    from adscan_internal.cli.check import (
        ExternalBinaryToolsCheckConfig,
        ExternalBinaryToolsCheckDeps,
    )

    eb_ok, eb_missing = deps.check_external_binary_tools(
        config=ExternalBinaryToolsCheckConfig(
            external_tools_config=config.external_tools_config,
            tools_install_dir=config.tools_install_dir,
            venv_path=config.venv_path,
            full_container_runtime=full_container_runtime,
            fix_mode=fix_mode,
        ),
        deps=ExternalBinaryToolsCheckDeps(
            expand_effective_user_path=deps.expand_effective_user_path,
            preflight_install_dns=deps.preflight_install_dns,
            setup_external_tool=deps.setup_external_tool,
            print_info=deps.print_info,
            print_success=deps.print_success,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
        ),
    )
    if not eb_ok:
        all_ok = False

    # 6. Check ligolo-ng runtime tooling used for pivot tunnels.
    ligolo_ok = check_ligolo_ng_runtime_tooling(
        full_container_runtime=full_container_runtime,
        deps=deps,
    )
    if not ligolo_ok:
        all_ok = False

    # 7. Check Wordlists (delegated to WordlistService)
    deps.print_info("Checking for wordlists...")
    wordlist_service = deps.WordlistService(wordlists_dir=config.wordlists_install_dir)
    w_all_ok, w_details = wordlist_service.verify_all(fix=fix_mode)
    for wl_name, status in w_details.items():
        if status.startswith("found"):
            deps.print_success(f"{wl_name} {status}")
        elif "installed" in status:
            deps.print_success(f"{wl_name} {status}")
        else:
            deps.print_error(f"{wl_name} {status}")
    if not w_all_ok:
        all_ok = False

    # 8. Check Docker and Docker Compose (if BloodHound CE is used) - delegated helper
    from adscan_internal.cli.check import (
        DockerComposeCheckConfig,
        DockerComposeCheckDeps,
    )

    docker_ok = deps.check_docker_compose(
        config=DockerComposeCheckConfig(
            bh_mode=bh_mode,
            fix_mode=fix_mode,
            full_container_runtime=full_container_runtime,
            bloodhound_ce_dir=config.bloodhound_ce_dir,
        ),
        deps=DockerComposeCheckDeps(
            is_docker_official_installed=deps.is_docker_official_installed,
            is_docker_compose_plugin_available=deps.is_docker_compose_plugin_available,
            check_bloodhound_ce_running=deps.check_bloodhound_ce_running,
            start_bloodhound_ce=deps.start_bloodhound_ce,
            get_bloodhound_cli_executable_path=deps.get_bloodhound_cli_executable_path,
            is_docker_env=deps.is_docker_env,
            expand_effective_user_path=deps.expand_effective_user_path,
            path_exists=deps.os_path_exists,
            path_access=deps.os_path_access,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_success=deps.print_success,
            print_success_verbose=deps.print_success_verbose,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
            print_instruction=deps.print_instruction,
            print_panel=deps.print_panel,
            print_exception=deps.print_exception,
            telemetry_capture_exception=deps.telemetry_capture_exception,
        ),
    )
    if not docker_ok:
        all_ok = False

    # 9. Check Rust tools (rusthound-ce) - delegated helper
    from adscan_internal.cli.check import (
        RustToolsCheckConfig,
        RustToolsCheckDeps,
    )

    rust_ok = deps.check_rust_tools(
        config=RustToolsCheckConfig(
            full_container_runtime=full_container_runtime,
            fix_mode=fix_mode,
        ),
        deps=RustToolsCheckDeps(
            is_rustup_available=deps.is_rustup_available,
            get_rusthound_verification_status=deps.get_rusthound_verification_status,
            configure_cargo_path=deps.configure_cargo_path,
            shutil_which=deps.shutil_which,
            os_environ=deps.os_environ,
            print_info=deps.print_info,
            print_success=deps.print_success,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
        ),
    )
    if not rust_ok:
        all_ok = False

    # 10. Check Go toolchain (always) and htb-cli (CI-only) - delegated helper
    from adscan_internal.cli.check import (
        GoToolchainCheckConfig,
        GoToolchainCheckDeps,
    )

    go_ok = deps.check_go_toolchain(
        config=GoToolchainCheckConfig(
            full_container_runtime=full_container_runtime,
            fix_mode=fix_mode,
            session_env=session_env,
        ),
        deps=GoToolchainCheckDeps(
            configure_go_official_path=deps.configure_go_official_path,
            configure_go_path=deps.configure_go_path,
            is_go_available=deps.is_go_available,
            is_go_bin_in_path=deps.is_go_bin_in_path,
            is_htb_cli_installed=deps.is_htb_cli_installed,
            is_htb_cli_accessible=deps.is_htb_cli_accessible,
            os_environ=deps.os_environ,
            subprocess_run=deps.subprocess_run,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_success=deps.print_success,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
        ),
    )
    if not go_ok:
        all_ok = False

    # 11. Check pyenv and Python version management - delegated helper
    from adscan_internal.cli.check import (
        PyenvCheckConfig,
        PyenvCheckDeps,
        check_pyenv_status as check_pyenv_status_fn,
    )

    pyenv_ok = check_pyenv_status_fn(
        config=PyenvCheckConfig(
            full_container_runtime=full_container_runtime,
            fix_mode=fix_mode,
            python_version=config.python_version,
            venv_path=config.venv_path,
        ),
        deps=PyenvCheckDeps(
            check_and_ensure_pyenv_status=deps.check_and_ensure_pyenv_status,
            install_pyenv_python_and_venv=deps.install_pyenv_python_and_venv,
            expand_effective_user_path=deps.expand_effective_user_path,
            regenerate_pyenv_shims=deps.regenerate_pyenv_shims,
            fix_pyenv_shims_permissions=deps.fix_pyenv_shims_permissions,
            mark_sensitive=deps.mark_sensitive,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_success=deps.print_success,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
            print_instruction=deps.print_instruction,
            print_panel=deps.print_panel,
            print_exception=deps.print_exception,
            telemetry_capture_exception=deps.telemetry_capture_exception,
        ),
    )
    if not pyenv_ok:
        all_ok = False

    if all_ok:
        deps.print_success(
            "All checks passed! adscan installation appears to be complete."
        )
        deps.print_instruction("Now you can start the tool with adscan start")

        # Final consolidated summary table
        deps.print_check_summary(all_ok)
        deps.set_last_check_session_extra(
            {
                "fix_mode": fix_mode,
                "fix_trigger": fix_trigger or ("flag" if fix_mode else None),
                "pre_fix_failed": pre_fix_failed if fix_mode else None,
                "missing_tools_count": len(missing_tools),
                "tool_version_issues_count": len(tool_version_issues),
                "missing_system_packages_count": missing_system_packages_count,
                "dnsmasq_occupies_53": dnsmasq_occupies_53_for_check,
                "unbound_ok": unbound_ok_for_check,
            }
        )

        if fix_mode:
            deps.telemetry_capture(
                "check_fix_completed",
                properties={
                    "trigger": fix_trigger or "flag",
                    "success": True,
                    "pre_fix_failed": pre_fix_failed,
                    "missing_tools_count": len(missing_tools),
                    "tool_version_issues_count": len(tool_version_issues),
                    "missing_system_packages_count": missing_system_packages_count,
                    "dnsmasq_occupies_53": dnsmasq_occupies_53_for_check,
                    "unbound_ok": unbound_ok_for_check,
                },
            )
        else:
            deps.telemetry_capture(
                "check_completed",
                properties={
                    "success": True,
                    "missing_tools_count": len(missing_tools),
                    "tool_version_issues_count": len(tool_version_issues),
                    "missing_system_packages_count": missing_system_packages_count,
                    "dnsmasq_occupies_53": dnsmasq_occupies_53_for_check,
                    "unbound_ok": unbound_ok_for_check,
                },
            )
        return all_ok
    else:
        recovery_guidance = get_check_failure_recovery_guidance(
            full_container_runtime=full_container_runtime
        )
        deps.print_error("Some checks failed. Please review the messages above.")
        deps.print_instruction(recovery_guidance.instruction)
        if recovery_guidance.follow_up_message:
            deps.print_info(recovery_guidance.follow_up_message)
        docs_url = "https://www.adscanpro.com/docs/guides/troubleshooting?utm_source=cli&utm_medium=check_failed"
        deps.print_info(
            f"💡 Troubleshooting guide: [link={docs_url}]adscanpro.com/docs/guides/troubleshooting[/link]"
        )
        deps.track_docs_link_shown("check_failed", docs_url)
        deps.print_check_summary(False)
        deps.set_last_check_session_extra(
            {
                "fix_mode": fix_mode,
                "fix_trigger": fix_trigger or ("flag" if fix_mode else None),
                "pre_fix_failed": pre_fix_failed if fix_mode else None,
                "missing_tools_count": len(missing_tools),
                "tool_version_issues_count": len(tool_version_issues),
                "missing_system_packages_count": missing_system_packages_count,
                "dnsmasq_occupies_53": dnsmasq_occupies_53_for_check,
                "unbound_ok": unbound_ok_for_check,
            }
        )

        if fix_mode:
            deps.telemetry_capture(
                "check_fix_completed",
                properties={
                    "trigger": fix_trigger or "flag",
                    "success": False,
                    "pre_fix_failed": pre_fix_failed,
                    "missing_tools_count": len(missing_tools),
                    "tool_version_issues_count": len(tool_version_issues),
                    "missing_system_packages_count": missing_system_packages_count,
                    "dnsmasq_occupies_53": dnsmasq_occupies_53_for_check,
                    "unbound_ok": unbound_ok_for_check,
                },
            )
            return False

        deps.telemetry_capture(
            "check_completed",
            properties={
                "success": False,
                "missing_tools_count": len(missing_tools),
                "tool_version_issues_count": len(tool_version_issues),
                "missing_system_packages_count": missing_system_packages_count,
                "dnsmasq_occupies_53": dnsmasq_occupies_53_for_check,
                "unbound_ok": unbound_ok_for_check,
            },
        )

        # Offer to run `--fix` interactively when possible.
        offer_fix = should_offer_interactive_check_repair(
            args=config.args,
            ci_env=deps.os_getenv("CI"),
            stdin_isatty=deps.sys_stdin_isatty(),
            guidance=recovery_guidance,
        )
        if offer_fix:
            deps.telemetry_capture(
                "check_fix_prompt_shown",
                properties={
                    "missing_tools_count": len(missing_tools),
                    "tool_version_issues_count": len(tool_version_issues),
                    "missing_system_packages_count": missing_system_packages_count,
                },
            )
            deps.print_warning("Some issues can often be fixed automatically.")
            proceed = deps.confirm_ask(
                str(recovery_guidance.interactive_prompt),
                default=True,
            )
            if proceed:
                deps.telemetry_capture("check_fix_prompt_accepted")
                deps.print_info("Running check with --fix...")
                fix_args = deps.argparse_namespace(**vars(config.args))
                fix_args.fix = True
                fix_args.fix_trigger = "prompt"
                fix_args.pre_fix_failed = True
                fix_success = deps.handle_check(fix_args)
                deps.telemetry_capture(
                    "check_fix_prompt_result",
                    properties={"success": bool(fix_success)},
                )
                deps.telemetry_capture(
                    "check_recovery",
                    properties={"method": "prompt", "recovered": bool(fix_success)},
                )
                return bool(fix_success)

            deps.telemetry_capture("check_fix_prompt_declined")
            deps.telemetry_capture(
                "check_recovery",
                properties={"method": "prompt_declined", "recovered": False},
            )

        offer_continue = should_offer_failed_check_override(
            args=config.args,
            ci_env=deps.os_getenv("CI"),
            stdin_isatty=deps.sys_stdin_isatty(),
        )
        if offer_continue:
            deps.print_warning(
                "You can continue anyway, but some features may fail or behave incorrectly until the issues above are repaired."
            )
            proceed_anyway = deps.confirm_ask(
                "Continue using ADscan anyway despite failed checks?",
                default=False,
            )
            if proceed_anyway:
                deps.telemetry_capture("check_override_accepted")
                deps.telemetry_capture(
                    "check_recovery",
                    properties={"method": "override", "recovered": True},
                )
                deps.print_warning(
                    "Proceeding despite failed checks at user request."
                )
                return True

            deps.telemetry_capture("check_override_declined")
            deps.telemetry_capture(
                "check_recovery",
                properties={"method": "override_declined", "recovered": False},
            )

        return False


def build_check_config_deps(
    *,
    args: Any | None,
    adscan_base_dir: str,
    tools_install_dir: str,
    wordlists_install_dir: str,
    tool_venvs_base_dir: str,
    venv_path: str,
    bloodhound_ce_dir: str,
    core_requirements: List[str],
    pip_tools_config: Dict[str, Any],
    external_tools_config: Dict[str, Any],
    system_packages_config: Dict[str, str],
    python_version: str,
    # All the dependency functions
    is_full_adscan_container_runtime: Callable[[], bool],
    determine_session_environment: Callable[[], str],
    get_bloodhound_mode: Callable[[], str],
    ensure_dir_writable: Callable[..., bool],
    check_virtual_environment_fn: Callable[..., tuple[bool, bool]],
    check_core_dependencies_fn: Callable[..., bool],
    check_external_tools_fn: Callable[..., bool],
    check_system_packages_fn: Callable[..., tuple[bool, List[str]]],
    check_dns_resolver_fn: Callable[..., bool],
    check_external_binary_tools_fn: Callable[..., tuple[bool, List[str]]],
    check_docker_compose_fn: Callable[..., bool],
    check_rust_tools_fn: Callable[..., bool],
    check_go_toolchain_fn: Callable[..., bool],
    check_pyenv_status_fn: Callable[..., bool],
    is_libreoffice_available: Callable[[], tuple[bool, str]],
    print_check_summary: Callable[[bool], None],
    WordlistService: type,
    run_command: Callable[..., object],
    get_clean_env_for_compilation: Callable[[], Dict[str, str]],
    parse_requirement_spec: Callable[[str], Any],
    get_python_package_version: Callable[..., str | None],
    assess_version_compliance: Callable[..., bool],
    get_installed_vcs_reference: Callable[..., str | None],
    get_installed_vcs_reference_by_url: Callable[..., str | None],
    normalize_vcs_repo_url: Callable[[str], str],
    vcs_reference_matches: Callable[..., bool],
    build_venv_exec_env: Callable[..., Dict[str, str]],
    check_executable_help_works: Callable[..., bool],
    fix_isolated_python_tool_venv: Callable[..., bool],
    diagnose_manspider_help_failure: Callable[..., None],
    ensure_isolated_tool_extra_specs_installed: Callable[..., bool],
    verify_system_packages: Callable[..., tuple[bool, List[str]]],
    apply_effective_user_home_to_env: Callable[..., Dict[str, str]],
    sudo_validate: Callable[..., bool],
    is_unbound_listening_local: Callable[[], bool],
    get_port_53_listeners_text: Callable[[], str],
    extract_process_names_from_ss: Callable[[str], List[str]],
    stop_dns_resolver_service_for_unbound: Callable[[], bool],
    start_unbound_without_systemd: Callable[[], bool],
    start_unbound_without_systemd_via_sudo: Callable[[], bool],
    is_systemd_available: Callable[[], bool],
    build_effective_user_env_for_command: Callable[..., Dict[str, str]],
    sudo_prefix_args: Callable[..., List[str]],
    expand_effective_user_path: Callable[[str], str],
    preflight_install_dns: Callable[[], bool],
    setup_external_tool: Callable[..., bool],
    is_docker_official_installed: Callable[[], tuple[bool, str]],
    is_docker_compose_plugin_available: Callable[[], tuple[bool, str]],
    check_bloodhound_ce_running: Callable[[], bool],
    start_bloodhound_ce: Callable[[], bool],
    get_bloodhound_cli_executable_path: Callable[[], str],
    is_docker_env: Callable[[], bool],
    is_rustup_available: Callable[[], tuple[bool, str]],
    get_rusthound_verification_status: Callable[[], Dict[str, Any]],
    configure_cargo_path: Callable[[], bool],
    configure_go_official_path: Callable[[], bool],
    configure_go_path: Callable[[], bool],
    is_go_available: Callable[[], tuple[bool, str]],
    is_go_bin_in_path: Callable[[], tuple[bool, str]],
    is_htb_cli_installed: Callable[[], tuple[bool, str]],
    is_htb_cli_accessible: Callable[[], tuple[bool, str]],
    check_and_ensure_pyenv_status: Callable[..., Dict[str, Any]],
    install_pyenv_python_and_venv: Callable[..., tuple[bool, List[str], str]],
    regenerate_pyenv_shims: Callable[[], bool],
    fix_pyenv_shims_permissions: Callable[[], bool],
    telemetry_capture: Callable[[str, Dict[str, Any]], None],
    telemetry_capture_exception: Callable[[BaseException], None],
    print_info: Callable[[str], None],
    print_info_verbose: Callable[[str], None],
    print_info_debug: Callable[[str], None],
    print_success: Callable[[str], None],
    print_success_verbose: Callable[[str], None],
    print_warning: Callable[[str], None],
    print_error: Callable[[str], None],
    print_instruction: Callable[[str], None],
    print_panel: Callable[..., None],
    print_exception: Callable[..., None],
    confirm_ask: Callable[..., bool],
    track_docs_link_shown: Callable[[str, str], None],
    os_getenv: Callable[[str, str | None], str | None],
    os_path_exists: Callable[[str], bool],
    os_path_access: Callable[[str, int], bool],
    sys_stdin_isatty: Callable[[], bool],
    argparse_namespace: type,
    shutil_which: Callable[[str], str | None],
    os_environ: Dict[str, str],
    subprocess_run: Callable[..., Any],
    mark_sensitive: Callable[..., Any],
    set_last_check_session_extra: Callable[[Dict[str, Any] | None], None],
    handle_check: Callable[[Any], bool],
) -> tuple[CheckConfig, CheckDeps]:
    """Build CheckConfig and CheckDeps from provided dependencies.

    This helper function constructs the configuration and dependency bundles
    needed for run_check, allowing handle_check in adscan.py to be a minimal wrapper.

    Returns:
        Tuple of (CheckConfig, CheckDeps) ready to pass to run_check.
    """
    config = CheckConfig(
        args=args,
        adscan_base_dir=adscan_base_dir,
        tools_install_dir=tools_install_dir,
        wordlists_install_dir=wordlists_install_dir,
        tool_venvs_base_dir=tool_venvs_base_dir,
        venv_path=venv_path,
        bloodhound_ce_dir=bloodhound_ce_dir,
        core_requirements=core_requirements,
        pip_tools_config=pip_tools_config,
        external_tools_config=external_tools_config,
        system_packages_config=system_packages_config,
        python_version=python_version,
    )

    deps = CheckDeps(
        is_full_adscan_container_runtime=is_full_adscan_container_runtime,
        determine_session_environment=determine_session_environment,
        get_bloodhound_mode=get_bloodhound_mode,
        ensure_dir_writable=ensure_dir_writable,
        check_virtual_environment=check_virtual_environment_fn,
        check_core_dependencies=check_core_dependencies_fn,
        check_external_tools=check_external_tools_fn,
        check_system_packages=check_system_packages_fn,
        check_dns_resolver=check_dns_resolver_fn,
        check_external_binary_tools=check_external_binary_tools_fn,
        check_docker_compose=check_docker_compose_fn,
        check_rust_tools=check_rust_tools_fn,
        check_go_toolchain=check_go_toolchain_fn,
        check_pyenv_status=check_pyenv_status_fn,
        is_libreoffice_available=is_libreoffice_available,
        print_check_summary=print_check_summary,
        WordlistService=WordlistService,
        run_command=run_command,
        get_clean_env_for_compilation=get_clean_env_for_compilation,
        parse_requirement_spec=parse_requirement_spec,
        get_python_package_version=get_python_package_version,
        assess_version_compliance=assess_version_compliance,
        get_installed_vcs_reference=get_installed_vcs_reference,
        get_installed_vcs_reference_by_url=get_installed_vcs_reference_by_url,
        normalize_vcs_repo_url=normalize_vcs_repo_url,
        vcs_reference_matches=vcs_reference_matches,
        build_venv_exec_env=build_venv_exec_env,
        check_executable_help_works=check_executable_help_works,
        fix_isolated_python_tool_venv=fix_isolated_python_tool_venv,
        diagnose_manspider_help_failure=diagnose_manspider_help_failure,
        ensure_isolated_tool_extra_specs_installed=ensure_isolated_tool_extra_specs_installed,
        verify_system_packages=verify_system_packages,
        apply_effective_user_home_to_env=apply_effective_user_home_to_env,
        sudo_validate=sudo_validate,
        is_unbound_listening_local=is_unbound_listening_local,
        get_port_53_listeners_text=get_port_53_listeners_text,
        extract_process_names_from_ss=extract_process_names_from_ss,
        stop_dns_resolver_service_for_unbound=stop_dns_resolver_service_for_unbound,
        start_unbound_without_systemd=start_unbound_without_systemd,
        start_unbound_without_systemd_via_sudo=start_unbound_without_systemd_via_sudo,
        is_systemd_available=is_systemd_available,
        build_effective_user_env_for_command=build_effective_user_env_for_command,
        sudo_prefix_args=sudo_prefix_args,
        expand_effective_user_path=expand_effective_user_path,
        preflight_install_dns=preflight_install_dns,
        setup_external_tool=setup_external_tool,
        is_docker_official_installed=is_docker_official_installed,
        is_docker_compose_plugin_available=is_docker_compose_plugin_available,
        check_bloodhound_ce_running=check_bloodhound_ce_running,
        start_bloodhound_ce=start_bloodhound_ce,
        get_bloodhound_cli_executable_path=get_bloodhound_cli_executable_path,
        is_docker_env=is_docker_env,
        is_rustup_available=is_rustup_available,
        get_rusthound_verification_status=get_rusthound_verification_status,
        configure_cargo_path=configure_cargo_path,
        configure_go_official_path=configure_go_official_path,
        configure_go_path=configure_go_path,
        is_go_available=is_go_available,
        is_go_bin_in_path=is_go_bin_in_path,
        is_htb_cli_installed=is_htb_cli_installed,
        is_htb_cli_accessible=is_htb_cli_accessible,
        check_and_ensure_pyenv_status=check_and_ensure_pyenv_status,
        install_pyenv_python_and_venv=install_pyenv_python_and_venv,
        regenerate_pyenv_shims=regenerate_pyenv_shims,
        fix_pyenv_shims_permissions=fix_pyenv_shims_permissions,
        telemetry_capture=telemetry_capture,
        telemetry_capture_exception=telemetry_capture_exception,
        print_info=print_info,
        print_info_verbose=print_info_verbose,
        print_info_debug=print_info_debug,
        print_success=print_success,
        print_success_verbose=print_success_verbose,
        print_warning=print_warning,
        print_error=print_error,
        print_instruction=print_instruction,
        print_panel=print_panel,
        print_exception=print_exception,
        confirm_ask=confirm_ask,
        track_docs_link_shown=track_docs_link_shown,
        os_getenv=os_getenv,
        os_path_exists=os_path_exists,
        os_path_access=os_path_access,
        sys_stdin_isatty=sys_stdin_isatty,
        argparse_namespace=argparse_namespace,
        shutil_which=shutil_which,
        os_environ=os_environ,
        subprocess_run=subprocess_run,
        mark_sensitive=mark_sensitive,
        set_last_check_session_extra=set_last_check_session_extra,
        handle_check=handle_check,
    )

    return config, deps


@dataclass
class AdscanCheckContext:
    """Context object containing all references from adscan.py needed for check.

    This allows handle_check to be a minimal wrapper by bundling all adscan.py
    references into a single object.
    """

    # Configuration values
    adscan_base_dir: str
    tools_install_dir: str
    wordlists_install_dir: str
    tool_venvs_base_dir: str
    venv_path: str
    bloodhound_ce_dir: str
    core_requirements: List[str]
    pip_tools_config: Dict[str, Any]
    external_tools_config: Dict[str, Any]
    system_packages_config: Dict[str, str]
    python_version: str

    # Functions from adscan.py
    is_full_adscan_container_runtime: Callable[[], bool]
    determine_session_environment: Callable[[], str]
    get_bloodhound_mode: Callable[[], str]
    ensure_dir_writable: Callable[..., bool]
    check_virtual_environment_fn: Callable[..., tuple[bool, bool]]
    check_core_dependencies_fn: Callable[..., bool]
    check_external_tools_fn: Callable[..., bool]
    check_system_packages_fn: Callable[..., tuple[bool, List[str]]]
    check_dns_resolver_fn: Callable[..., bool]
    check_external_binary_tools_fn: Callable[..., tuple[bool, List[str]]]
    check_docker_compose_fn: Callable[..., bool]
    check_rust_tools_fn: Callable[..., bool]
    check_go_toolchain_fn: Callable[..., bool]
    check_pyenv_status_fn: Callable[..., bool]
    is_libreoffice_available: Callable[[], tuple[bool, str]]
    print_check_summary: Callable[[bool], None]
    WordlistService: type
    run_command: Callable[..., object]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    parse_requirement_spec: Callable[[str], Any]
    get_python_package_version: Callable[..., str | None]
    assess_version_compliance: Callable[..., bool]
    get_installed_vcs_reference: Callable[..., str | None]
    get_installed_vcs_reference_by_url: Callable[..., str | None]
    normalize_vcs_repo_url: Callable[[str], str]
    vcs_reference_matches: Callable[..., bool]
    build_venv_exec_env: Callable[..., Dict[str, str]]
    check_executable_help_works: Callable[..., bool]
    fix_isolated_python_tool_venv: Callable[..., bool]
    diagnose_manspider_help_failure: Callable[..., None]
    ensure_isolated_tool_extra_specs_installed: Callable[..., bool]
    verify_system_packages: Callable[..., tuple[bool, List[str]]]
    apply_effective_user_home_to_env: Callable[..., Dict[str, str]]
    sudo_validate: Callable[..., bool]
    is_unbound_listening_local: Callable[[], bool]
    get_port_53_listeners_text: Callable[[], str]
    extract_process_names_from_ss: Callable[[str], List[str]]
    stop_dns_resolver_service_for_unbound: Callable[[], bool]
    start_unbound_without_systemd: Callable[[], bool]
    start_unbound_without_systemd_via_sudo: Callable[[], bool]
    is_systemd_available: Callable[[], bool]
    build_effective_user_env_for_command: Callable[..., Dict[str, str]]
    sudo_prefix_args: Callable[..., List[str]]
    expand_effective_user_path: Callable[[str], str]
    preflight_install_dns: Callable[[], bool]
    setup_external_tool: Callable[..., bool]
    is_docker_official_installed: Callable[[], tuple[bool, str]]
    is_docker_compose_plugin_available: Callable[[], tuple[bool, str]]
    check_bloodhound_ce_running: Callable[[], bool]
    start_bloodhound_ce: Callable[[], bool]
    get_bloodhound_cli_executable_path: Callable[[], str]
    is_docker_env: Callable[[], bool]
    is_rustup_available: Callable[[], tuple[bool, str]]
    get_rusthound_verification_status: Callable[[], Dict[str, Any]]
    configure_cargo_path: Callable[[], bool]
    configure_go_official_path: Callable[[], bool]
    configure_go_path: Callable[[], bool]
    is_go_available: Callable[[], tuple[bool, str]]
    is_go_bin_in_path: Callable[[], tuple[bool, str]]
    is_htb_cli_installed: Callable[[], tuple[bool, str]]
    is_htb_cli_accessible: Callable[[], tuple[bool, str]]
    check_and_ensure_pyenv_status: Callable[..., Dict[str, Any]]
    install_pyenv_python_and_venv: Callable[..., tuple[bool, List[str], str]]
    regenerate_pyenv_shims: Callable[[], bool]
    fix_pyenv_shims_permissions: Callable[[], bool]
    telemetry_capture: Callable[[str, Dict[str, Any]], None]
    telemetry_capture_exception: Callable[[BaseException], None]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_info_debug: Callable[[str], None]
    print_success: Callable[[str], None]
    print_success_verbose: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    print_panel: Callable[..., None]
    print_exception: Callable[..., None]
    confirm_ask: Callable[..., bool]
    track_docs_link_shown: Callable[[str, str], None]
    os_getenv: Callable[[str, str | None], str | None]
    os_path_exists: Callable[[str], bool]
    os_path_access: Callable[[str, int], bool]
    sys_stdin_isatty: Callable[[], bool]
    argparse_namespace: type
    shutil_which: Callable[[str], str | None]
    os_environ: Dict[str, str]
    subprocess_run: Callable[..., Any]
    mark_sensitive: Callable[..., Any]
    set_last_check_session_extra: Callable[[Dict[str, Any] | None], None]
    handle_check: Callable[[Any], bool]


def build_adscan_check_context(
    *,
    adscan_base_dir: str,
    tools_install_dir: str,
    wordlists_install_dir: str,
    tool_venvs_base_dir: str,
    venv_path: str,
    bloodhound_ce_dir: str,
    core_requirements: List[str],
    pip_tools_config: Dict[str, Any],
    external_tools_config: Dict[str, Any],
    system_packages_config: Dict[str, str],
    python_version: str,
    is_full_adscan_container_runtime: Callable[[], bool],
    determine_session_environment: Callable[[], str],
    get_bloodhound_mode: Callable[[], str],
    ensure_dir_writable: Callable[..., bool],
    check_virtual_environment_fn: Callable[..., tuple[bool, bool]],
    check_core_dependencies_fn: Callable[..., bool],
    check_external_tools_fn: Callable[..., bool],
    check_system_packages_fn: Callable[..., tuple[bool, List[str]]],
    check_dns_resolver_fn: Callable[..., bool],
    check_external_binary_tools_fn: Callable[..., tuple[bool, List[str]]],
    check_docker_compose_fn: Callable[..., bool],
    check_rust_tools_fn: Callable[..., bool],
    check_go_toolchain_fn: Callable[..., bool],
    check_pyenv_status_fn: Callable[..., bool],
    is_libreoffice_available: Callable[[], tuple[bool, str]],
    print_check_summary: Callable[[bool], None],
    WordlistService: type,
    run_command: Callable[..., object],
    get_clean_env_for_compilation: Callable[[], Dict[str, str]],
    parse_requirement_spec: Callable[[str], Any],
    get_python_package_version: Callable[..., str | None],
    assess_version_compliance: Callable[..., bool],
    get_installed_vcs_reference: Callable[..., str | None],
    get_installed_vcs_reference_by_url: Callable[..., str | None],
    normalize_vcs_repo_url: Callable[[str], str],
    vcs_reference_matches: Callable[..., bool],
    build_venv_exec_env: Callable[..., Dict[str, str]],
    check_executable_help_works: Callable[..., bool],
    fix_isolated_python_tool_venv: Callable[..., bool],
    diagnose_manspider_help_failure: Callable[..., None],
    ensure_isolated_tool_extra_specs_installed: Callable[..., bool],
    verify_system_packages: Callable[..., tuple[bool, List[str]]],
    apply_effective_user_home_to_env: Callable[..., Dict[str, str]],
    sudo_validate: Callable[..., bool],
    is_unbound_listening_local: Callable[[], bool],
    get_port_53_listeners_text: Callable[[], str],
    extract_process_names_from_ss: Callable[[str], List[str]],
    stop_dns_resolver_service_for_unbound: Callable[[], bool],
    start_unbound_without_systemd: Callable[[], bool],
    start_unbound_without_systemd_via_sudo: Callable[[], bool],
    is_systemd_available: Callable[[], bool],
    build_effective_user_env_for_command: Callable[..., Dict[str, str]],
    sudo_prefix_args: Callable[..., List[str]],
    expand_effective_user_path: Callable[[str], str],
    preflight_install_dns: Callable[[], bool],
    setup_external_tool: Callable[..., bool],
    is_docker_official_installed: Callable[[], tuple[bool, str]],
    is_docker_compose_plugin_available: Callable[[], tuple[bool, str]],
    check_bloodhound_ce_running: Callable[[], bool],
    start_bloodhound_ce: Callable[[], bool],
    get_bloodhound_cli_executable_path: Callable[[], str],
    is_docker_env: Callable[[], bool],
    is_rustup_available: Callable[[], tuple[bool, str]],
    get_rusthound_verification_status: Callable[[], Dict[str, Any]],
    configure_cargo_path: Callable[[], bool],
    configure_go_official_path: Callable[[], bool],
    configure_go_path: Callable[[], bool],
    is_go_available: Callable[[], tuple[bool, str]],
    is_go_bin_in_path: Callable[[], tuple[bool, str]],
    is_htb_cli_installed: Callable[[], tuple[bool, str]],
    is_htb_cli_accessible: Callable[[], tuple[bool, str]],
    check_and_ensure_pyenv_status: Callable[..., Dict[str, Any]],
    install_pyenv_python_and_venv: Callable[..., tuple[bool, List[str], str]],
    regenerate_pyenv_shims: Callable[[], bool],
    fix_pyenv_shims_permissions: Callable[[], bool],
    telemetry_capture: Callable[[str, Dict[str, Any]], None],
    telemetry_capture_exception: Callable[[BaseException], None],
    print_info: Callable[[str], None],
    print_info_verbose: Callable[[str], None],
    print_info_debug: Callable[[str], None],
    print_success: Callable[[str], None],
    print_success_verbose: Callable[[str], None],
    print_warning: Callable[[str], None],
    print_error: Callable[[str], None],
    print_instruction: Callable[[str], None],
    print_panel: Callable[..., None],
    print_exception: Callable[..., None],
    confirm_ask: Callable[..., bool],
    track_docs_link_shown: Callable[[str, str], None],
    os_getenv: Callable[[str, str | None], str | None],
    os_path_exists: Callable[[str], bool],
    os_path_access: Callable[[str, int], bool],
    sys_stdin_isatty: Callable[[], bool],
    argparse_namespace: type,
    shutil_which: Callable[[str], str | None],
    os_environ: Dict[str, str],
    subprocess_run: Callable[..., Any],
    mark_sensitive: Callable[..., Any],
    set_last_check_session_extra: Callable[[Dict[str, Any] | None], None],
    handle_check: Callable[[Any], bool],
) -> AdscanCheckContext:
    """Build AdscanCheckContext from individual parameters.

    This function constructs the context object from all the references passed
    from adscan.py, allowing handle_check to be a minimal wrapper.

    Returns:
        AdscanCheckContext ready to pass to build_check_from_adscan_context.
    """
    return AdscanCheckContext(
        adscan_base_dir=adscan_base_dir,
        tools_install_dir=tools_install_dir,
        wordlists_install_dir=wordlists_install_dir,
        tool_venvs_base_dir=tool_venvs_base_dir,
        venv_path=venv_path,
        bloodhound_ce_dir=bloodhound_ce_dir,
        core_requirements=core_requirements,
        pip_tools_config=pip_tools_config,
        external_tools_config=external_tools_config,
        system_packages_config=system_packages_config,
        python_version=python_version,
        is_full_adscan_container_runtime=is_full_adscan_container_runtime,
        determine_session_environment=determine_session_environment,
        get_bloodhound_mode=get_bloodhound_mode,
        ensure_dir_writable=ensure_dir_writable,
        check_virtual_environment_fn=check_virtual_environment_fn,
        check_core_dependencies_fn=check_core_dependencies_fn,
        check_external_tools_fn=check_external_tools_fn,
        check_system_packages_fn=check_system_packages_fn,
        check_dns_resolver_fn=check_dns_resolver_fn,
        check_external_binary_tools_fn=check_external_binary_tools_fn,
        check_docker_compose_fn=check_docker_compose_fn,
        check_rust_tools_fn=check_rust_tools_fn,
        check_go_toolchain_fn=check_go_toolchain_fn,
        check_pyenv_status_fn=check_pyenv_status_fn,
        is_libreoffice_available=is_libreoffice_available,
        print_check_summary=print_check_summary,
        WordlistService=WordlistService,
        run_command=run_command,
        get_clean_env_for_compilation=get_clean_env_for_compilation,
        parse_requirement_spec=parse_requirement_spec,
        get_python_package_version=get_python_package_version,
        assess_version_compliance=assess_version_compliance,
        get_installed_vcs_reference=get_installed_vcs_reference,
        get_installed_vcs_reference_by_url=get_installed_vcs_reference_by_url,
        normalize_vcs_repo_url=normalize_vcs_repo_url,
        vcs_reference_matches=vcs_reference_matches,
        build_venv_exec_env=build_venv_exec_env,
        check_executable_help_works=check_executable_help_works,
        fix_isolated_python_tool_venv=fix_isolated_python_tool_venv,
        diagnose_manspider_help_failure=diagnose_manspider_help_failure,
        ensure_isolated_tool_extra_specs_installed=ensure_isolated_tool_extra_specs_installed,
        verify_system_packages=verify_system_packages,
        apply_effective_user_home_to_env=apply_effective_user_home_to_env,
        sudo_validate=sudo_validate,
        is_unbound_listening_local=is_unbound_listening_local,
        get_port_53_listeners_text=get_port_53_listeners_text,
        extract_process_names_from_ss=extract_process_names_from_ss,
        stop_dns_resolver_service_for_unbound=stop_dns_resolver_service_for_unbound,
        start_unbound_without_systemd=start_unbound_without_systemd,
        start_unbound_without_systemd_via_sudo=start_unbound_without_systemd_via_sudo,
        is_systemd_available=is_systemd_available,
        build_effective_user_env_for_command=build_effective_user_env_for_command,
        sudo_prefix_args=sudo_prefix_args,
        expand_effective_user_path=expand_effective_user_path,
        preflight_install_dns=preflight_install_dns,
        setup_external_tool=setup_external_tool,
        is_docker_official_installed=is_docker_official_installed,
        is_docker_compose_plugin_available=is_docker_compose_plugin_available,
        check_bloodhound_ce_running=check_bloodhound_ce_running,
        start_bloodhound_ce=start_bloodhound_ce,
        get_bloodhound_cli_executable_path=get_bloodhound_cli_executable_path,
        is_docker_env=is_docker_env,
        is_rustup_available=is_rustup_available,
        get_rusthound_verification_status=get_rusthound_verification_status,
        configure_cargo_path=configure_cargo_path,
        configure_go_official_path=configure_go_official_path,
        configure_go_path=configure_go_path,
        is_go_available=is_go_available,
        is_go_bin_in_path=is_go_bin_in_path,
        is_htb_cli_installed=is_htb_cli_installed,
        is_htb_cli_accessible=is_htb_cli_accessible,
        check_and_ensure_pyenv_status=check_and_ensure_pyenv_status,
        install_pyenv_python_and_venv=install_pyenv_python_and_venv,
        regenerate_pyenv_shims=regenerate_pyenv_shims,
        fix_pyenv_shims_permissions=fix_pyenv_shims_permissions,
        telemetry_capture=telemetry_capture,
        telemetry_capture_exception=telemetry_capture_exception,
        print_info=print_info,
        print_info_verbose=print_info_verbose,
        print_info_debug=print_info_debug,
        print_success=print_success,
        print_success_verbose=print_success_verbose,
        print_warning=print_warning,
        print_error=print_error,
        print_instruction=print_instruction,
        print_panel=print_panel,
        print_exception=print_exception,
        confirm_ask=confirm_ask,
        track_docs_link_shown=track_docs_link_shown,
        os_getenv=os_getenv,
        os_path_exists=os_path_exists,
        os_path_access=os_path_access,
        sys_stdin_isatty=sys_stdin_isatty,
        argparse_namespace=argparse_namespace,
        shutil_which=shutil_which,
        os_environ=os_environ,
        subprocess_run=subprocess_run,
        mark_sensitive=mark_sensitive,
        set_last_check_session_extra=set_last_check_session_extra,
        handle_check=handle_check,
    )


def build_check_from_adscan_context(
    *,
    args: Any | None,
    context: AdscanCheckContext,
) -> tuple[CheckConfig, CheckDeps]:
    """Build CheckConfig and CheckDeps from AdscanCheckContext.

    This is a convenience wrapper around build_check_config_deps that accepts
    a context object instead of individual parameters, allowing handle_check
    in adscan.py to be a minimal wrapper.

    Args:
        args: Optional argparse.Namespace with check arguments.
        context: AdscanCheckContext containing all references from adscan.py.

    Returns:
        Tuple of (CheckConfig, CheckDeps) ready to pass to run_check.
    """
    return build_check_config_deps(
        args=args,
        adscan_base_dir=context.adscan_base_dir,
        tools_install_dir=context.tools_install_dir,
        wordlists_install_dir=context.wordlists_install_dir,
        tool_venvs_base_dir=context.tool_venvs_base_dir,
        venv_path=context.venv_path,
        bloodhound_ce_dir=context.bloodhound_ce_dir,
        core_requirements=context.core_requirements,
        pip_tools_config=context.pip_tools_config,
        external_tools_config=context.external_tools_config,
        system_packages_config=context.system_packages_config,
        python_version=context.python_version,
        is_full_adscan_container_runtime=context.is_full_adscan_container_runtime,
        determine_session_environment=context.determine_session_environment,
        get_bloodhound_mode=context.get_bloodhound_mode,
        ensure_dir_writable=context.ensure_dir_writable,
        check_virtual_environment_fn=context.check_virtual_environment_fn,
        check_core_dependencies_fn=context.check_core_dependencies_fn,
        check_external_tools_fn=context.check_external_tools_fn,
        check_system_packages_fn=context.check_system_packages_fn,
        check_dns_resolver_fn=context.check_dns_resolver_fn,
        check_external_binary_tools_fn=context.check_external_binary_tools_fn,
        check_docker_compose_fn=context.check_docker_compose_fn,
        check_rust_tools_fn=context.check_rust_tools_fn,
        check_go_toolchain_fn=context.check_go_toolchain_fn,
        check_pyenv_status_fn=context.check_pyenv_status_fn,
        is_libreoffice_available=context.is_libreoffice_available,
        print_check_summary=context.print_check_summary,
        WordlistService=context.WordlistService,
        run_command=context.run_command,
        get_clean_env_for_compilation=context.get_clean_env_for_compilation,
        parse_requirement_spec=context.parse_requirement_spec,
        get_python_package_version=context.get_python_package_version,
        assess_version_compliance=context.assess_version_compliance,
        get_installed_vcs_reference=context.get_installed_vcs_reference,
        get_installed_vcs_reference_by_url=context.get_installed_vcs_reference_by_url,
        normalize_vcs_repo_url=context.normalize_vcs_repo_url,
        vcs_reference_matches=context.vcs_reference_matches,
        build_venv_exec_env=context.build_venv_exec_env,
        check_executable_help_works=context.check_executable_help_works,
        fix_isolated_python_tool_venv=context.fix_isolated_python_tool_venv,
        diagnose_manspider_help_failure=context.diagnose_manspider_help_failure,
        ensure_isolated_tool_extra_specs_installed=context.ensure_isolated_tool_extra_specs_installed,
        verify_system_packages=context.verify_system_packages,
        apply_effective_user_home_to_env=context.apply_effective_user_home_to_env,
        sudo_validate=context.sudo_validate,
        is_unbound_listening_local=context.is_unbound_listening_local,
        get_port_53_listeners_text=context.get_port_53_listeners_text,
        extract_process_names_from_ss=context.extract_process_names_from_ss,
        stop_dns_resolver_service_for_unbound=context.stop_dns_resolver_service_for_unbound,
        start_unbound_without_systemd=context.start_unbound_without_systemd,
        start_unbound_without_systemd_via_sudo=context.start_unbound_without_systemd_via_sudo,
        is_systemd_available=context.is_systemd_available,
        build_effective_user_env_for_command=context.build_effective_user_env_for_command,
        sudo_prefix_args=context.sudo_prefix_args,
        expand_effective_user_path=context.expand_effective_user_path,
        preflight_install_dns=context.preflight_install_dns,
        setup_external_tool=context.setup_external_tool,
        is_docker_official_installed=context.is_docker_official_installed,
        is_docker_compose_plugin_available=context.is_docker_compose_plugin_available,
        check_bloodhound_ce_running=context.check_bloodhound_ce_running,
        start_bloodhound_ce=context.start_bloodhound_ce,
        get_bloodhound_cli_executable_path=context.get_bloodhound_cli_executable_path,
        is_docker_env=context.is_docker_env,
        is_rustup_available=context.is_rustup_available,
        get_rusthound_verification_status=context.get_rusthound_verification_status,
        configure_cargo_path=context.configure_cargo_path,
        configure_go_official_path=context.configure_go_official_path,
        configure_go_path=context.configure_go_path,
        is_go_available=context.is_go_available,
        is_go_bin_in_path=context.is_go_bin_in_path,
        is_htb_cli_installed=context.is_htb_cli_installed,
        is_htb_cli_accessible=context.is_htb_cli_accessible,
        check_and_ensure_pyenv_status=context.check_and_ensure_pyenv_status,
        install_pyenv_python_and_venv=context.install_pyenv_python_and_venv,
        regenerate_pyenv_shims=context.regenerate_pyenv_shims,
        fix_pyenv_shims_permissions=context.fix_pyenv_shims_permissions,
        telemetry_capture=context.telemetry_capture,
        telemetry_capture_exception=context.telemetry_capture_exception,
        print_info=context.print_info,
        print_info_verbose=context.print_info_verbose,
        print_info_debug=context.print_info_debug,
        print_success=context.print_success,
        print_success_verbose=context.print_success_verbose,
        print_warning=context.print_warning,
        print_error=context.print_error,
        print_instruction=context.print_instruction,
        print_panel=context.print_panel,
        print_exception=context.print_exception,
        confirm_ask=context.confirm_ask,
        track_docs_link_shown=context.track_docs_link_shown,
        os_getenv=context.os_getenv,
        os_path_exists=context.os_path_exists,
        os_path_access=context.os_path_access,
        sys_stdin_isatty=context.sys_stdin_isatty,
        argparse_namespace=context.argparse_namespace,
        shutil_which=context.shutil_which,
        os_environ=context.os_environ,
        subprocess_run=context.subprocess_run,
        mark_sensitive=context.mark_sensitive,
        set_last_check_session_extra=context.set_last_check_session_extra,
        handle_check=context.handle_check,
    )
