"""Helpers for managing isolated Python tool virtual environments.

This module provides functions for creating, managing, and verifying isolated
Python tool virtual environments used by ADscan tools like manspider, netexec, etc.

The functions here intentionally rely on dependency injection so we don't
introduce import cycles back into `adscan.py`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
import re
import shutil
from typing import Any, Dict


@dataclass(frozen=True)
class IsolatedToolsDeps:
    """Dependency bundle for isolated tool operations."""

    run_command: Callable[..., Any]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    parse_requirement_spec: Callable[[str], Dict[str, Any]]
    run_pip_install_with_retries: Callable[..., None]
    configure_ssl_certificates: Callable[[Dict[str, str]], None]
    is_pyenv_available: Callable[..., tuple[bool, str, list[str] | None]]
    install_pyenv_python_and_venv: Callable[..., tuple[bool, str, str | None]]
    apply_effective_user_home_to_env: Callable[[Dict[str, str]], None]
    expand_effective_user_path: Callable[[str], str]
    get_nxc_base_dir: Callable[[], str]
    sudo_validate: Callable[[], bool]
    telemetry_capture_exception: Callable[[BaseException], None]
    telemetry_capture: Callable[..., None]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_info_debug: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    print_exception: Callable[..., None]
    mark_sensitive: Callable[[str, str], str]


def build_venv_exec_env(
    venv_path: str,
    python_executable: str,
    *,
    deps: IsolatedToolsDeps,
) -> dict[str, str]:
    """Build a clean environment for executing commands inside an isolated venv.

    Args:
        venv_path: Path to the venv directory (e.g. ~/.adscan/tool_venvs/netexec/venv)
        python_executable: Path to the venv's python executable (used to derive bin dir)
        deps: Dependency bundle for isolated tool operations

    Returns:
        Environment mapping suitable for subprocess execution.
    """
    venv_bin_path = os.path.dirname(python_executable)
    env = deps.get_clean_env_for_compilation()
    env["PATH"] = f"{venv_bin_path}{os.pathsep}{env.get('PATH', '')}"
    env["VIRTUAL_ENV"] = venv_path
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    return env


def ensure_isolated_tool_extra_specs_installed(
    *,
    tool_name: str,
    tool_python: str,
    venv_path: str,
    extra_specs: list[str],
    deps: IsolatedToolsDeps,
) -> bool:
    """Ensure extra pip specs are installed inside an existing isolated tool venv.

    We use this for optional-but-required-in-practice dependencies that upstream
    may not declare (e.g., ldap3 NTLM requiring MD4 via pycryptodome on newer
    Python versions).

    Args:
        tool_name: Name of the tool (for logging)
        tool_python: Path to the tool's Python executable
        venv_path: Path to the venv directory
        extra_specs: List of extra pip specs to install
        deps: Dependency bundle for isolated tool operations

    Returns:
        True if all extra specs were installed successfully, False otherwise
    """
    if not extra_specs:
        return True

    pip_env = os.environ.copy()
    pip_env["VIRTUAL_ENV"] = venv_path
    venv_bin = os.path.dirname(tool_python)
    pip_env["PATH"] = f"{venv_bin}:{pip_env.get('PATH', '')}"
    pip_env.pop("LD_LIBRARY_PATH", None)
    pip_env.pop("PYTHONHOME", None)
    pip_env.pop("PYTHONPATH", None)
    deps.configure_ssl_certificates(pip_env)
    pip_env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    pip_env.setdefault("PIP_NO_INPUT", "1")
    pip_env.setdefault("PIP_DEFAULT_TIMEOUT", "300")

    try:
        for extra_spec in extra_specs:
            extra_spec_info = deps.parse_requirement_spec(extra_spec)
            extra_force_reinstall = bool(
                extra_spec_info.get("is_vcs") and extra_spec_info.get("vcs_reference")
            )
            extra_pip_cmd = [
                tool_python,
                "-m",
                "pip",
                "install",
                "--upgrade",
                "--retries",
                "5",
                "--timeout",
                "300",
            ]
            if extra_force_reinstall:
                extra_pip_cmd.append("--force-reinstall")
            extra_pip_cmd.append(extra_spec)
            deps.run_pip_install_with_retries(
                extra_pip_cmd,
                env=pip_env,
                attempts=3,
                backoff_seconds=15,
                label=f"pip install ({tool_name} extra)",
            )
        return True
    except Exception as exc:  # pragma: no cover - environment dependent
        deps.telemetry_capture_exception(exc)
        deps.print_warning(
            f"{tool_name}: failed to ensure extra dependencies are installed."
        )
        deps.print_exception(show_locals=False, exception=exc)
        return False


def check_executable_help_works(
    tool_name: str,
    executable_path: str,
    env: dict[str, str],
    *,
    deps: IsolatedToolsDeps,
    timeout_seconds: int = 8,
    fix: bool = False,
) -> bool:
    """Verify an executable is runnable by invoking its help output.

    This catches broken installs where the binary exists but crashes at runtime.

    Args:
        tool_name: Friendly tool name for messaging.
        executable_path: Path to the executable to invoke.
        env: Environment to use (should include venv PATH and VIRTUAL_ENV).
        deps: Dependency bundle for isolated tool operations
        timeout_seconds: Timeout for the help invocation.
        fix: Whether to attempt automatic fixes for permission issues.

    Returns:
        True if the tool seems runnable, False otherwise.
    """

    def _help_output_looks_valid(stdout_text: str, stderr_text: str) -> bool:
        """Return True when output strongly suggests help ran successfully.

        Some tools exit with non-zero for `--help`/`-h` even though they are runnable.
        We accept those as valid if the output looks like a help/usage screen and
        does not contain a traceback.
        """
        stdout_lower = (stdout_text or "").lower()
        stderr_lower = (stderr_text or "").lower()
        combined_lower = f"{stdout_lower}\n{stderr_lower}"
        if "traceback (most recent call last)" in combined_lower:
            return False
        return any(
            token in combined_lower
            for token in [
                "usage:",
                "options:",
                "positional arguments:",
                "show this help message",
                "--help",
                "-h, --help",
            ]
        )

    def _diagnose_help_failure(output_text: str) -> None:
        """Best-effort diagnosis for tools that crash on help execution.

        Keep messaging user-safe: do not print raw traceback lines (paths/domains).
        """
        lowered = (output_text or "").lower()
        if "traceback (most recent call last)" not in lowered:
            return

        module_match = re.search(
            r"no module named ['\"]([^'\"]+)['\"]",
            output_text or "",
            flags=re.IGNORECASE,
        )
        if module_match:
            missing = module_match.group(1)
            deps.print_warning(
                f"{tool_name} failed to start due to a missing Python dependency."
            )
            marked_tool_venv = deps.mark_sensitive(
                f"~/.adscan/tool_venvs/{tool_name}/venv",
                "path",
            )
            deps.print_instruction(
                "Try: `adscan install` (repairs/recreates isolated tool envs)."
            )
            deps.print_instruction(
                f"If it still fails, remove {marked_tool_venv} and rerun `adscan install`."
            )
            deps.telemetry_capture(
                "tool_help_probe_import_error",
                properties={"tool": tool_name, "missing_module": missing},
            )
            return

        if "importerror" in lowered:
            deps.print_warning(f"{tool_name} failed to start due to a Python import error.")
            marked_tool_venv = deps.mark_sensitive(
                f"~/.adscan/tool_venvs/{tool_name}/venv",
                "path",
            )
            deps.print_instruction(
                "Try: `adscan install` (repairs/recreates isolated tool envs)."
            )
            deps.print_instruction(
                f"If it still fails, remove {marked_tool_venv} and rerun `adscan install`."
            )
            deps.telemetry_capture(
                "tool_help_probe_import_error",
                properties={"tool": tool_name, "missing_module": None},
            )
            return

        if "cannot open shared object file" in lowered or "undefined symbol" in lowered:
            deps.print_warning(
                f"{tool_name} failed to start due to a missing system library."
            )
            deps.print_instruction(
                "Try reinstalling dependencies (Debian/Kali): `sudo apt-get update && sudo apt-get install -f -y`"
            )
            deps.telemetry_capture(
                "tool_help_probe_native_error",
                properties={"tool": tool_name},
            )
            return

        # Generic crash
        deps.print_warning(f"{tool_name} crashed while executing its help command.")
        marked_tool_venv = deps.mark_sensitive(
            f"~/.adscan/tool_venvs/{tool_name}/venv",
            "path",
        )
        deps.print_instruction(
            "Try: `adscan install` (repairs/recreates isolated tool envs)."
        )
        deps.print_instruction(
            f"If it still fails, remove {marked_tool_venv} and rerun `adscan install`."
        )
        deps.telemetry_capture(
            "tool_help_probe_crash",
            properties={"tool": tool_name},
        )

    help_variants: list[list[str]] = [
        [executable_path, "--help"],
        [executable_path, "-h"],
    ]
    attempted_nxc_fix = False
    attempted_manspider_fix = False
    for cmd in help_variants:
        try:
            result = deps.run_command(
                cmd,
                check=False,
                capture_output=True,
                env=env,
                timeout=timeout_seconds,
            )
        except Exception as e:  # pragma: no cover - depends on runtime environment
            deps.telemetry_capture_exception(e)
            deps.print_error(f"{tool_name}: failed to execute help command ({cmd[-1]})")
            deps.print_exception(exception=e)
            return False

        if result.returncode == 0:
            return True

        combined = f"{(result.stdout or '').strip()}\n{(result.stderr or '').strip()}"
        if _help_output_looks_valid(result.stdout or "", result.stderr or ""):
            deps.print_info_verbose(
                f"[check] {tool_name} help probe ({cmd[-1]}) returned {result.returncode} but output looks like valid usage; accepting."
            )
            return True

        # Add a safe diagnosis (no raw traceback output).
        _diagnose_help_failure(combined)

        # MANSPIDER writes logs to ~/.manspider/logs by default and can crash if
        # that directory is owned by another user (legacy root installs).
        if (
            tool_name == "manspider"
            and not attempted_manspider_fix
            and "permissionerror" in combined.lower()
            and ".manspider" in combined
        ):
            attempted_manspider_fix = True
            manspider_dir = deps.expand_effective_user_path("~/.manspider")
            manspider_logs_dir = os.path.join(manspider_dir, "logs")
            deps.print_warning(
                f"{tool_name} cannot write to its log directory ({manspider_logs_dir})."
            )
            if not fix:
                deps.print_info_verbose(
                    "Run `adscan check --fix` to attempt automatic permission repairs."
                )
                continue

            try:
                os.makedirs(manspider_logs_dir, exist_ok=True)

                # Prefer fixing ownership to the effective invoking user.
                import pwd

                target_user = (
                    os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
                )
                target_group = None
                try:
                    target_group = pwd.getpwuid(os.getuid()).pw_name
                except Exception:
                    target_group = None

                if os.geteuid() == 0:
                    deps.run_command(
                        [
                            "chown",
                            "-R",
                            f"{target_user}:{target_group or target_user}",
                            manspider_dir,
                        ],
                        check=False,
                        capture_output=True,
                        timeout=30,
                    )
                else:
                    if deps.sudo_validate():
                        deps.run_command(
                            [
                                "sudo",
                                "-n",
                                "chown",
                                "-R",
                                f"{target_user}:{target_group or target_user}",
                                manspider_dir,
                            ],
                            check=False,
                            capture_output=True,
                            timeout=30,
                        )

                retry = deps.run_command(
                    cmd,
                    check=False,
                    capture_output=True,
                    env=env,
                    timeout=timeout_seconds,
                )
                if retry.returncode == 0:
                    deps.print_success(
                        f"{tool_name} is now runnable after repairing permissions."
                    )
                    return True
                result = retry
                combined = (
                    f"{(result.stdout or '').strip()}\n{(result.stderr or '').strip()}"
                )
            except Exception as fix_e:  # pragma: no cover - environment dependent
                deps.telemetry_capture_exception(fix_e)
                deps.print_info_debug(
                    f"[check] Failed to auto-repair manspider permissions: {fix_e}"
                )

        if (
            not attempted_nxc_fix
            and "permissionerror" in combined.lower()
            and ".nxc" in combined
        ):
            attempted_nxc_fix = True
            nxc_dir = deps.get_nxc_base_dir()
            deps.print_warning(
                f"{tool_name} cannot write to its NetExec state directory ({nxc_dir})."
            )
            if not fix:
                deps.print_info_verbose(
                    "Run `adscan check --fix` to attempt automatic permission repairs."
                )
                continue
            try:
                import pwd

                target_user = (
                    os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
                )
                target_group = None
                try:
                    target_group = pwd.getpwuid(os.getuid()).pw_name
                except Exception:
                    target_group = None

                if os.geteuid() == 0:
                    # Running as root: fix directly.
                    deps.run_command(
                        [
                            "chown",
                            "-R",
                            f"{target_user}:{target_group or target_user}",
                            nxc_dir,
                        ],
                        check=False,
                        capture_output=True,
                        timeout=15,
                    )
                else:
                    # Validate sudo so we can prompt if needed, then fix permissions.
                    if deps.sudo_validate():
                        deps.run_command(
                            [
                                "sudo",
                                "-n",
                                "chown",
                                "-R",
                                f"{target_user}:{target_group or target_user}",
                                nxc_dir,
                            ],
                            check=False,
                            capture_output=True,
                            timeout=30,
                        )
                # Retry same help command once after attempting the fix.
                retry = deps.run_command(
                    cmd,
                    check=False,
                    capture_output=True,
                    env=env,
                    timeout=timeout_seconds,
                )
                if retry.returncode == 0:
                    deps.print_success(
                        f"{tool_name} is now runnable after repairing permissions."
                    )
                    return True
                # If retry failed, continue loop and log details below.
                result = retry
                combined = (
                    f"{(result.stdout or '').strip()}\n{(result.stderr or '').strip()}"
                )
            except Exception as fix_e:  # pragma: no cover - environment dependent
                deps.telemetry_capture_exception(fix_e)
                deps.print_info_debug(
                    f"[check] Failed to auto-repair NetExec permissions: {fix_e}"
                )

        output_preview = "\n".join(
            s
            for s in [(result.stdout or "").strip(), (result.stderr or "").strip()]
            if s
        )[:800]
        deps.print_info_verbose(
            f"[check] {tool_name} help probe ({cmd[-1]}) returned {result.returncode}. "
            f"Output preview: {output_preview or '<no output>'}"
        )

    return False


def fix_isolated_python_tool_venv(
    tool_key: str,
    *,
    tool_venvs_base_dir: str,
    venv_path: str,
    python_version: str,
    pip_tools_config: Any,  # PipToolsConfig type
    deps: IsolatedToolsDeps,
) -> bool:
    """Best-effort repair for an isolated Python tool venv.

    This recreates the tool venv and reinstalls the tool spec defined in PipToolsConfig.

    Args:
        tool_key: Key in PipToolsConfig (e.g., "manspider", "netexec").
        tool_venvs_base_dir: Base directory for tool venvs (e.g., ~/.adscan/tool_venvs)
        venv_path: Path to the main ADscan venv
        python_version: Pyenv Python version to use for venv creation.
        pip_tools_config: PipToolsConfig instance to get tool configuration
        deps: Dependency bundle for isolated tool operations

    Returns:
        True if the tool was reinstalled successfully, False otherwise.
    """
    config = pip_tools_config.get(tool_key)
    if not config:
        deps.print_info_debug(f"[fix] Unknown tool key for venv repair: {tool_key}")
        return False

    tool_dir_name = tool_key
    install_spec = config.get("spec")
    if not install_spec:
        deps.print_info_debug(f"[fix] No install spec found for tool: {tool_dir_name}")
        return False

    spec_info = deps.parse_requirement_spec(install_spec)
    extra_specs = config.get("extra_specs", [])

    tool_specific_venv_base = os.path.join(tool_venvs_base_dir, tool_dir_name)
    tool_specific_venv_path = os.path.join(tool_specific_venv_base, "venv")
    tool_specific_python = os.path.join(tool_specific_venv_path, "bin", "python")

    deps.print_info(f"Attempting to repair isolated tool environment: {tool_dir_name}")

    try:
        if os.path.isdir(tool_specific_venv_path):
            shutil.rmtree(tool_specific_venv_path, ignore_errors=True)

        os.makedirs(tool_specific_venv_base, exist_ok=True)

        pyenv_ok, _, pyenv_cmd_list = deps.is_pyenv_available(os.environ)
        if not pyenv_ok or not pyenv_cmd_list:
            deps.print_warning(
                "pyenv not available; cannot repair isolated tool environments automatically."
            )
            deps.print_instruction("Run: adscan install (installs/configures pyenv)")
            return False

        pyenv_root_result = deps.run_command(
            pyenv_cmd_list + ["root"], capture_output=True, check=False
        )
        pyenv_root = (
            (pyenv_root_result.stdout or "").strip() if pyenv_root_result else ""
        )
        pyenv_python = os.path.join(
            pyenv_root, "versions", python_version, "bin", "python"
        )

        if not pyenv_root or not os.path.exists(pyenv_python):
            # Best-effort: install/configure pyenv + Python version. This also ensures the main ADscan venv exists.
            ok, _, _ = deps.install_pyenv_python_and_venv(
                python_version=python_version, venv_path=venv_path
            )
            if not ok:
                return False
            pyenv_root_result = deps.run_command(
                pyenv_cmd_list + ["root"], capture_output=True, check=False
            )
            pyenv_root = (
                (pyenv_root_result.stdout or "").strip() if pyenv_root_result else ""
            )
            pyenv_python = os.path.join(
                pyenv_root, "versions", python_version, "bin", "python"
            )
            if not pyenv_root or not os.path.exists(pyenv_python):
                deps.print_warning(
                    "pyenv is available but required Python version is still missing."
                )
                return False

        clean_env = deps.get_clean_env_for_compilation()
        deps.apply_effective_user_home_to_env(clean_env)
        deps.run_command(
            [pyenv_python, "-m", "venv", tool_specific_venv_path],
            check=True,
            env=clean_env,
        )

        pip_env = os.environ.copy()
        pip_env["VIRTUAL_ENV"] = tool_specific_venv_path
        tool_venv_bin = os.path.dirname(tool_specific_python)
        pip_env["PATH"] = f"{tool_venv_bin}{os.pathsep}{pip_env.get('PATH', '')}"
        pip_env.pop("LD_LIBRARY_PATH", None)
        pip_env.pop("PYTHONHOME", None)
        pip_env.pop("PYTHONPATH", None)
        deps.configure_ssl_certificates(pip_env)

        force_reinstall = bool(
            spec_info.get("is_vcs") and spec_info.get("vcs_reference")
        )
        pip_cmd = [
            tool_specific_python,
            "-m",
            "pip",
            "install",
            "--upgrade",
            "--retries",
            "5",
            "--timeout",
            "300",
        ]
        if force_reinstall:
            pip_cmd.append("--force-reinstall")
        pip_cmd.append(install_spec)

        deps.run_pip_install_with_retries(
            pip_cmd,
            env=pip_env,
            attempts=3,
            backoff_seconds=15,
            label=f"pip install ({tool_dir_name})",
        )

        for extra_spec in extra_specs:
            extra_spec_info = deps.parse_requirement_spec(extra_spec)
            extra_force_reinstall = bool(
                extra_spec_info.get("is_vcs") and extra_spec_info.get("vcs_reference")
            )
            extra_pip_cmd = [
                tool_specific_python,
                "-m",
                "pip",
                "install",
                "--upgrade",
                "--retries",
                "5",
                "--timeout",
                "300",
            ]
            if extra_force_reinstall:
                extra_pip_cmd.append("--force-reinstall")
            extra_pip_cmd.append(extra_spec)
            deps.run_pip_install_with_retries(
                extra_pip_cmd,
                env=pip_env,
                attempts=3,
                backoff_seconds=15,
                label=f"pip install ({tool_dir_name} extra)",
            )

        return True
    except Exception as exc:  # pragma: no cover - environment dependent
        deps.telemetry_capture_exception(exc)
        deps.print_warning(f"Failed to repair tool environment for {tool_dir_name}.")
        deps.print_exception(show_locals=False, exception=exc)
        return False


def diagnose_manspider_help_failure(
    tool_python: str,
    env: dict[str, str],
    *,
    deps: IsolatedToolsDeps,
) -> None:
    """Best-effort diagnosis for MANSPIDER runtime failures.

    MANSPIDER imports `magic` (python-magic). When python-magic or its libmagic
    runtime dependency is missing, `manspider --help` often crashes immediately.

    Args:
        tool_python: The isolated venv python executable for manspider.
        env: Environment configured for the isolated venv execution.
        deps: Dependency bundle for isolated tool operations
    """
    try:
        probe = deps.run_command(
            [tool_python, "-c", "import magic; print('ok')"],
            check=False,
            capture_output=True,
            env=env,
            timeout=6,
        )
    except Exception as e:  # pragma: no cover - runtime dependent
        deps.telemetry_capture_exception(e)
        deps.print_info_verbose("[check] manspider diagnosis probe failed to execute.")
        deps.print_exception(exception=e)
        return

    combined = f"{(probe.stdout or '').strip()}\n{(probe.stderr or '').strip()}".strip()
    if probe.returncode == 0:
        deps.print_info_verbose(
            "[check] manspider diagnosis: python-magic import ok; failure likely inside manspider itself."
        )
        return

    lowered = combined.lower()
    if "no module named" in lowered and "magic" in lowered:
        deps.print_warning(
            "manspider failed to start because the Python dependency `python-magic` is missing."
        )
        deps.print_instruction(
            "Fix: re-run `adscan install` (it installs python-magic inside manspider's isolated venv)."
        )
        return

    if "libmagic" in lowered or "magic.mgc" in lowered:
        deps.print_warning(
            "manspider failed to start because the system libmagic runtime is missing or misconfigured."
        )
        deps.print_instruction(
            "Fix (Debian/Kali): `sudo apt-get update && sudo apt-get install -y libmagic1`"
        )
        return

    deps.print_info_verbose(
        "[check] manspider diagnosis: unknown failure while importing `magic` (output sanitized)."
    )

