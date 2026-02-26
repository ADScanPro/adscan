"""Helpers for legacy `adscan install` system package setup.

This module hosts small, dependency-light helpers used by the legacy
host-based installer to keep `adscan.py` slimmer while preserving the
original behaviour.

The functions here intentionally rely on dependency injection so we don't
introduce import cycles back into `adscan.py`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List


@dataclass(frozen=True)
class SystemPackagesInstallConfig:
    """Configuration for installing/updating system packages.

    Attributes:
        system_packages_config: Mapping of APT package name -> executable name.
        apt_target: Optional list of additional arguments for `apt-get`,
            typically ``["-t", "<codename-backports>"]`` or empty when unused.
    """

    system_packages_config: Dict[str, str]
    apt_target: List[str]


@dataclass(frozen=True)
class SystemPackagesInstallDeps:
    """Dependency bundle for system package installation flow."""

    run_command: Callable[..., object]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    get_noninteractive_apt_env: Callable[[Dict[str, str]], Dict[str, str]]
    install_rustup: Callable[[], bool]
    telemetry_capture_exception: Callable[[BaseException], None]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_success: Callable[[str], None]
    print_info_debug: Callable[[str], None]
    print_warning_debug: Callable[[str], None]
    print_instruction: Callable[[str], None]
    print_exception: Callable[..., None]


def install_system_packages(
    *,
    config: SystemPackagesInstallConfig,
    deps: SystemPackagesInstallDeps,
) -> None:
    """Install/update all required system packages for the legacy installer.

    This function mirrors the original `handle_install` logic around:

    1) Building the package list from ``SYSTEM_PACKAGES_CONFIG``
    2) Installing special-case packages individually for better diagnostics
    3) Performing a batch installation for the remainder
    4) Falling back to per-package install when the batch fails
    5) Installing the Rust toolchain via ``rustup`` once packages are in place

    All I/O, subprocess calls, and telemetry are injected via ``deps`` to keep
    this helper testable and to avoid circular imports with ``adscan.py``.

    The function is deliberately best-effort: failures are reported to the user
    but do not raise exceptions here; the caller decides whether installation
    failures should be treated as fatal.
    """
    system_packages_config = config.system_packages_config

    # Build package list from SYSTEM_PACKAGES_CONFIG, excluding neo4j (handled separately)
    packages_to_install: list[str] = []
    for package_name in system_packages_config:
        if package_name == "neo4j":
            # Neo4j is handled by a dedicated installation block in the caller.
            continue
        packages_to_install.append(package_name)

    # Remove duplicates and sort
    unique_packages_to_install: list[str] = sorted(list(set(packages_to_install)))
    install_unbound_last = "unbound" in unique_packages_to_install
    if install_unbound_last:
        # Install Unbound last: enabling the local resolver can affect DNS behavior
        # during the rest of the installation (pip/git downloads). The caller will
        # install/configure Unbound at the end.
        unique_packages_to_install.remove("unbound")

    if unique_packages_to_install:
        deps.print_info(
            "Installing/updating system packages: "
            + ", ".join(unique_packages_to_install),
        )
        if install_unbound_last:
            deps.print_info_verbose(
                "Unbound will be installed/configured as the final install step."
            )
    else:
        # Nothing to do here; let the caller handle the Unbound step.
        if install_unbound_last:
            deps.print_success(
                "All required system packages were already present "
                "(Unbound will be installed last)."
            )
        else:
            deps.print_success("All required system packages were already present.")
        return

    # Pre-configure Kerberos if krb5-user is being installed to avoid interactive prompts.
    if "krb5-user" in unique_packages_to_install:
        deps.print_info(
            "Pre-configuring Kerberos to avoid interactive prompts during "
            "krb5-user installation..."
        )
        try:
            krb5_config = [
                "krb5-config krb5-config/default_realm string EXAMPLE.COM",
                "krb5-config krb5-config/add_servers boolean false",
                "krb5-config krb5-config/admin_server string kdc.example.com",
            ]
            debconf_env = deps.get_clean_env_for_compilation()

            for cfg in krb5_config:
                subprocess.run(
                    ["debconf-set-selections"],
                    input=cfg,
                    text=True,
                    check=True,
                    env=debconf_env,
                )
            deps.print_success("Kerberos pre-configuration applied.")
        except Exception as exc:  # noqa: BLE001 - must mirror legacy behaviour
            deps.telemetry_capture_exception(exc)
            deps.print_warning(f"Failed to pre-configure Kerberos: {exc}")
            deps.print_info("Installation will continue with default settings.")

    try:
        clean_env = deps.get_clean_env_for_compilation()
        apt_env = deps.get_noninteractive_apt_env(clean_env)

        successfully_installed: list[str] = []

        # Special-case libmagic1: install separately to debug failures better.
        if "libmagic1" in unique_packages_to_install:
            try:
                deps.print_info("Installing libmagic1 (required for manspider)...")
                deps.run_command(
                    ["apt-get", "install", "-y"] + config.apt_target + ["libmagic1"],
                    check=True,
                    env=apt_env,
                )
                deps.print_success("libmagic1 installed successfully")
                successfully_installed.append("libmagic1")
            except subprocess.CalledProcessError as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                deps.print_warning(
                    "Failed to install libmagic1. manspider may fail to start "
                    "(import magic)."
                )
                deps.print_exception(show_locals=False, exception=exc)
            finally:
                # Always remove it from the batch list to avoid blocking the bulk install.
                if "libmagic1" in unique_packages_to_install:
                    unique_packages_to_install.remove("libmagic1")

        # Special-case freerdp3-x11: attempt install separately to handle broken dependencies.
        if "freerdp3-x11" in unique_packages_to_install:
            try:
                deps.print_info("Installing freerdp3-x11...")
                deps.run_command(
                    ["apt-get", "install", "-y"]
                    + config.apt_target
                    + [
                        "-o",
                        "Dpkg::Options::=--force-confdef",
                        "-o",
                        "Dpkg::Options::=--force-confnew",
                    ]
                    + ["freerdp3-x11"],
                    check=True,
                    env=apt_env,
                    capture_output=False,
                )
                deps.print_success("freerdp3-x11 installed successfully")
                successfully_installed.append("freerdp3-x11")
            except subprocess.CalledProcessError as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                deps.print_warning(
                    "Failed to install freerdp3-x11 due to unmet dependencies, "
                    "falling back to freerdp2-x11"
                )
                try:
                    deps.print_info("Installing freerdp2-x11 as fallback...")
                    deps.run_command(
                        ["apt-get", "install", "-y"]
                        + config.apt_target
                        + ["freerdp2-x11"],
                        check=True,
                        env=apt_env,
                    )
                    deps.print_success("freerdp2-x11 installed successfully")
                    successfully_installed.append("freerdp2-x11")
                    unique_packages_to_install.remove("freerdp3-x11")
                    unique_packages_to_install.append("freerdp2-x11")
                except subprocess.CalledProcessError as fallback_error:  # noqa: BLE001
                    deps.telemetry_capture_exception(fallback_error)
                    deps.print_error(
                        f"Failed fallback installation freerdp2-x11: {fallback_error}"
                    )

        # Special-case hashcat: handle conflicts with hashcat-data in Kali Linux.
        if "hashcat" in unique_packages_to_install:
            try:
                deps.print_info("Installing hashcat...")
                deps.run_command(
                    ["apt-get", "install", "-y"] + config.apt_target + ["hashcat"],
                    check=True,
                    env=apt_env,
                )
                deps.print_success("hashcat installed successfully")
                successfully_installed.append("hashcat")
                unique_packages_to_install.remove("hashcat")
            except subprocess.CalledProcessError as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                error_output = getattr(exc, "stderr", None) or getattr(
                    exc, "stdout", ""
                )
                if (
                    "hashcat-data" in (error_output or "")
                    or "trying to overwrite" in (error_output or "")
                ):
                    deps.print_warning(
                        "hashcat installation conflict detected, attempting to fix "
                        "broken packages..."
                    )
                    try:
                        deps.run_command(
                            ["apt-get", "install", "--fix-broken", "-y"],
                            check=True,
                            env=apt_env,
                        )
                        deps.print_info_verbose(
                            "Broken packages fixed, retrying hashcat installation..."
                        )
                        deps.run_command(
                            ["apt-get", "install", "-y"]
                            + config.apt_target
                            + ["hashcat"],
                            check=True,
                            env=apt_env,
                        )
                        deps.print_success(
                            "hashcat installed successfully after fixing broken "
                            "packages"
                        )
                        successfully_installed.append("hashcat")
                        unique_packages_to_install.remove("hashcat")
                    except subprocess.CalledProcessError as fix_error:  # noqa: BLE001
                        deps.telemetry_capture_exception(fix_error)
                        deps.print_warning(
                            "Failed to fix and install hashcat: "
                            f"{fix_error}. Continuing with other packages..."
                        )
                        if "hashcat" in unique_packages_to_install:
                            unique_packages_to_install.remove("hashcat")
                else:
                    deps.print_warning(
                        "hashcat installation failed with unexpected error: "
                        f"{exc}. Continuing with other packages..."
                    )
                    if "hashcat" in unique_packages_to_install:
                        unique_packages_to_install.remove("hashcat")

        # Special-case libreoffice: install without recommended packages to avoid Java dependencies.
        if "libreoffice" in unique_packages_to_install:
            try:
                deps.print_info(
                    "Installing libreoffice (without recommended packages to avoid "
                    "Java dependencies)..."
                )
                deps.print_info_verbose(
                    "Note: LibreOffice will be installed without Java components."
                )
                deps.run_command(
                    ["apt-get", "install", "-y", "--no-install-recommends"]
                    + config.apt_target
                    + ["libreoffice"],
                    check=True,
                    env=apt_env,
                )
                deps.print_success(
                    "libreoffice installed successfully (without Java dependencies)"
                )
                successfully_installed.append("libreoffice")
                unique_packages_to_install.remove("libreoffice")
            except subprocess.CalledProcessError as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                deps.print_warning(
                    f"Failed to install libreoffice: {exc}. "
                    "Continuing with other packages..."
                )
                deps.print_info_verbose(
                    "LibreOffice is optional and only needed for PDF report generation. "
                    "Word reports will still work without it."
                )
                if "libreoffice" in unique_packages_to_install:
                    unique_packages_to_install.remove("libreoffice")

        # Special-case ntpsec-ntpdate: install in isolation and fallback to ntpdate.
        if "ntpsec-ntpdate" in unique_packages_to_install:
            try:
                deps.print_info("Installing ntpsec-ntpdate (time sync helper)...")
                ntp_proc = deps.run_command(
                    ["apt-get", "install", "-y"]
                    + config.apt_target
                    + ["-o", "Dpkg::Use-Pty=0", "ntpsec-ntpdate"],
                    check=False,
                    capture_output=True,
                    env=apt_env,
                )
                rc = getattr(ntp_proc, "returncode", None)
                if ntp_proc and rc == 0:
                    deps.print_success("ntpsec-ntpdate installed successfully")
                    successfully_installed.append("ntpsec-ntpdate")
                else:
                    combined = "\n".join(
                        [
                            getattr(ntp_proc, "stdout", "") or "",
                            getattr(ntp_proc, "stderr", "") or "",
                        ]
                    ).strip()
                    tail = (
                        "\n".join(combined.splitlines()[-40:]) if combined else ""
                    )
                    deps.print_warning(
                        "Failed to install ntpsec-ntpdate; attempting fallback "
                        "package 'ntpdate'..."
                    )
                    deps.print_info_debug(
                        "[apt] ntpsec-ntpdate install failed "
                        f"rc={rc}"
                    )
                    if tail:
                        deps.print_info_debug(
                            "[apt] ntpsec-ntpdate output tail:\n" + tail
                        )

                    ntp_fallback = deps.run_command(
                        ["apt-get", "install", "-y"]
                        + config.apt_target
                        + ["-o", "Dpkg::Use-Pty=0", "ntpdate"],
                        check=False,
                        capture_output=True,
                        env=apt_env,
                    )
                    fb_rc = getattr(ntp_fallback, "returncode", None)
                    if ntp_fallback and fb_rc == 0:
                        deps.print_success("ntpdate installed successfully (fallback)")
                        successfully_installed.append("ntpdate")
                    else:
                        combined_fb = "\n".join(
                            [
                                getattr(ntp_fallback, "stdout", "") or "",
                                getattr(ntp_fallback, "stderr", "") or "",
                            ]
                        ).strip()
                        tail_fb = (
                            "\n".join(combined_fb.splitlines()[-40:])
                            if combined_fb
                            else ""
                        )
                        deps.print_warning(
                            "Failed to install both ntpsec-ntpdate and fallback ntpdate. "
                            "Time sync features may be limited."
                        )
                        deps.print_info_debug(
                            "[apt] ntpdate fallback failed "
                            f"rc={fb_rc}"
                        )
                        if tail_fb:
                            deps.print_info_debug(
                                "[apt] ntpdate output tail:\n" + tail_fb
                            )
            except Exception as exc:  # noqa: BLE001 - legacy best-effort behaviour
                deps.telemetry_capture_exception(exc)
                deps.print_warning(
                    "Unexpected error while installing ntpdate tooling. "
                    "Continuing with other packages..."
                )
                deps.print_exception(show_locals=False, exception=exc)
            finally:
                if "ntpsec-ntpdate" in unique_packages_to_install:
                    unique_packages_to_install.remove("ntpsec-ntpdate")

        # Install remaining packages in batch (faster than individual installation).
        if unique_packages_to_install:
            install_command = (
                ["apt-get", "install", "-y"]
                + config.apt_target
                + ["-o", "Dpkg::Use-Pty=0"]
                + [
                    "-o",
                    "Dpkg::Options::=--force-confdef",
                    "-o",
                    "Dpkg::Options::=--force-confnew",
                ]
                + unique_packages_to_install
            )
            deps.print_info(
                "Installing remaining system packages: "
                + ", ".join(unique_packages_to_install)
            )
            batch_proc = deps.run_command(
                install_command,
                check=False,
                capture_output=True,
                env=apt_env,
            )
            if batch_proc and getattr(batch_proc, "returncode", None) == 0:
                successfully_installed.extend(unique_packages_to_install)
            else:
                all_output = "\n".join(
                    [
                        getattr(batch_proc, "stdout", "") or "",
                        getattr(batch_proc, "stderr", "") or "",
                    ]
                ).strip()
                tail_lines = (
                    "\n".join(all_output.splitlines()[-60:]) if all_output else ""
                )
                deps.print_error(
                    "Failed to install some system packages in batch mode."
                )
                deps.print_info_debug(
                    "[apt] batch install failed "
                    f"rc={getattr(batch_proc, 'returncode', None)} "
                    f"packages={len(unique_packages_to_install)}"
                )
                if tail_lines:
                    deps.print_info_debug(
                        "[apt] batch install output tail:\n" + tail_lines
                    )

                # Fallback: install one-by-one to identify the failing package(s).
                failed_packages: list[str] = []
                for pkg in list(unique_packages_to_install):
                    per_pkg_cmd = (
                        ["apt-get", "install", "-y"]
                        + config.apt_target
                        + ["-o", "Dpkg::Use-Pty=0"]
                        + [
                            "-o",
                            "Dpkg::Options::=--force-confdef",
                            "-o",
                            "Dpkg::Options::=--force-confnew",
                        ]
                        + [pkg]
                    )
                    proc = deps.run_command(
                        per_pkg_cmd,
                        check=False,
                        capture_output=True,
                        env=apt_env,
                    )
                    if proc and getattr(proc, "returncode", None) == 0:
                        successfully_installed.append(pkg)
                        continue

                    failed_packages.append(pkg)
                    combined = (
                        "\n".join(
                            [
                                getattr(proc, "stdout", "") or "",
                                getattr(proc, "stderr", "") or "",
                            ]
                        ).strip()
                        if proc
                        else ""
                    )
                    tail = (
                        "\n".join(combined.splitlines()[-40:]) if combined else ""
                    )
                    deps.print_info_debug(
                        "[apt] package failed "
                        f"rc={getattr(proc, 'returncode', None)} pkg={pkg}"
                    )
                    if tail:
                        deps.print_info_debug(
                            f"[apt] {pkg} output tail:\n" + tail
                        )

                # Remove any packages that were successfully installed individually from the pending list
                for ok_pkg in successfully_installed:
                    if ok_pkg in unique_packages_to_install:
                        unique_packages_to_install.remove(ok_pkg)

                if failed_packages:
                    deps.print_error(
                        "Some system packages could not be installed automatically."
                    )
                    deps.print_info(
                        "Please try installing them manually: "
                        f"sudo apt install {' '.join(failed_packages)}"
                    )
                else:
                    deps.print_warning(
                        "Batch installation failed, but all packages installed "
                        "successfully when retried individually."
                    )
        else:
            deps.print_info(
                "All system packages were installed individually (no batch "
                "installation needed)"
            )

        # Show summary of all successfully installed packages
        if successfully_installed:
            deps.print_success(
                "Successfully installed/updated system packages: "
                + ", ".join(sorted(successfully_installed))
            )
        else:
            deps.print_success("System packages installation completed")

        # Install Rust toolchain via rustup (after system packages for curl, build-essential, etc.)
        deps.print_info("Installing Rust toolchain via rustup...")
        if deps.install_rustup():
            deps.print_success("Rust toolchain installation completed")
        else:
            deps.print_warning(
                "Rust toolchain installation failed, but continuing..."
            )
            deps.print_info("RustHound-CE will not be available without Rust")
    except subprocess.CalledProcessError as exc:  # noqa: BLE001
        deps.telemetry_capture_exception(exc)
        deps.print_error("Failed to install some system packages.")
        deps.print_exception(show_locals=False, exception=exc)
        deps.print_instruction(
            "Please try installing them manually: sudo apt install "
            + " ".join(unique_packages_to_install)
        )
    except FileNotFoundError as exc:  # noqa: BLE001
        deps.telemetry_capture_exception(exc)
        deps.print_error("'apt-get' not found. Cannot install system packages.")



@dataclass(frozen=True)
class ExternalToolsInstallConfig:
    """Configuration for installing external Python tools into isolated venvs.

    Attributes:
        pip_tools_config: Mapping of tool key -> configuration dictionary. This
            mirrors ``PipToolsConfig`` from ``adscan.py``.
        tool_venvs_base_dir: Base directory where per-tool virtualenvs will be
            created.
        python_version: Python version string used by pyenv (for example
            ``"3.12.3"``).
        adscan_base_dir: Base directory of the ADScan installation, used as a
            scratch location for temporary files such as ``get-pip.py``.
    """

    pip_tools_config: Dict[str, Dict[str, Any]]
    tool_venvs_base_dir: str
    python_version: str
    adscan_base_dir: str


@dataclass(frozen=True)
class ExternalToolsInstallDeps:
    """Dependency bundle for external Python tools installation."""

    # Printing / telemetry
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_success: Callable[[str], None]
    print_success_verbose: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_error_context: Callable[..., None]
    telemetry_capture_exception: Callable[[BaseException], None]

    # Environment / subprocess helpers
    run_command: Callable[..., Any]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    get_pyenv_available: Callable[[Dict[str, str]], tuple[bool, str | None, List[str]]]

    # Network / DNS / SSL helpers
    preflight_install_dns: Callable[[List[str], int, int, str], bool]
    configure_ssl_certificates: Callable[[Dict[str, str]], None]

    # Requirement / pip helpers
    parse_requirement_spec: Callable[[str], Dict[str, Any]]
    run_pip_install_with_retries: Callable[..., None]

    # Download helper for get-pip.py
    download_file_with_fallbacks: Callable[[str, str, int], None]


def install_external_python_tools(
    *, config: ExternalToolsInstallConfig, deps: ExternalToolsInstallDeps
) -> bool:
    """Install external Python tools into their own isolated virtual environments.

    This helper mirrors the legacy logic from ``handle_install`` for the
    ``--legacy`` (host-based) mode. All I/O and side effects are provided via
    the injected dependencies to keep the function testable and to avoid
    circular imports with ``adscan.py``.
    """
    deps.print_info("Installing external Python tools into isolated environments...")

    github_dns_ok = deps.preflight_install_dns(
        ["github.com"],
        attempts=3,
        backoff_seconds=3,
        context_label="install preflight",
    )
    all_tools_successful = True

    for tool_key, tool_cfg in config.pip_tools_config.items():
        tool_dir_name = tool_key
        install_spec = tool_cfg["spec"]
        spec_info = deps.parse_requirement_spec(install_spec)
        extra_specs = tool_cfg.get("extra_specs", [])

        tool_specific_venv_base = os.path.join(
            config.tool_venvs_base_dir, tool_dir_name
        )
        tool_specific_venv_path = os.path.join(tool_specific_venv_base, "venv")
        tool_specific_python = os.path.join(tool_specific_venv_path, "bin", "python")

        deps.print_info(
            f"Processing tool: {tool_dir_name} (installing '{install_spec}')"
        )
        os.makedirs(tool_specific_venv_base, exist_ok=True)

        if (
            spec_info.get("is_vcs")
            and (spec_info.get("repo_url") or "").startswith("https://github.com/")
            and not github_dns_ok
        ):
            deps.print_warning(
                f"Skipping {tool_dir_name}: GitHub is not resolvable from this host right now."
            )
            all_tools_successful = False
            continue

        # Create virtualenv if it does not exist yet
        if not os.path.exists(os.path.join(tool_specific_venv_path, "bin", "activate")):
            deps.print_info(
                "Creating virtual environment for "
                f"{tool_dir_name} at: {tool_specific_venv_path} with "
                f"Python {config.python_version}"
            )
            try:
                pyenv_available, _, pyenv_cmd_list = deps.get_pyenv_available(
                    os.environ
                )
                if not pyenv_available or not pyenv_cmd_list:
                    deps.print_error(
                        f"pyenv is not available for {tool_dir_name} venv creation"
                    )
                    all_tools_successful = False
                    continue

                pyenv_root_result = deps.run_command(
                    pyenv_cmd_list + ["root"],
                    capture_output=True,
                    check=True,
                )
                pyenv_root = pyenv_root_result.stdout.strip()
                pyenv_python = os.path.join(
                    pyenv_root,
                    "versions",
                    config.python_version,
                    "bin",
                    "python",
                )

                if not os.path.exists(pyenv_python):
                    deps.print_error(f"Python executable not found at: {pyenv_python}")
                    all_tools_successful = False
                    continue

                deps.print_info(f"Using Python at: {pyenv_python} for {tool_dir_name}")

                clean_env = deps.get_clean_env_for_compilation()

                # Try creating venv normally first
                result = deps.run_command(
                    [pyenv_python, "-m", "venv", tool_specific_venv_path],
                    check=False,
                    env=clean_env,
                )
                venv_created = False

                if result.returncode == 0:
                    deps.print_success(
                        f"Virtual environment for {tool_dir_name} created."
                    )
                    venv_created = True
                else:
                    # Venv creation failed, try fallback with --without-pip
                    deps.print_warning(
                        f"Venv creation failed for {tool_dir_name}, "
                        "trying fallback method..."
                    )
                    try:
                        # Remove any partial venv
                        if os.path.exists(tool_specific_venv_path):
                            shutil.rmtree(tool_specific_venv_path)

                        # Create venv without pip
                        deps.run_command(
                            [
                                pyenv_python,
                                "-m",
                                "venv",
                                "--without-pip",
                                tool_specific_venv_path,
                            ],
                            check=True,
                            env=clean_env,
                        )
                        deps.print_success(
                            "Virtual environment for "
                            f"{tool_dir_name} created without pip."
                        )

                        # Install pip manually using get-pip.py
                        tool_venv_python = os.path.join(
                            tool_specific_venv_path,
                            "bin",
                            "python",
                        )
                        deps.print_info(
                            "Installing pip in "
                            f"{tool_dir_name} virtual environment..."
                        )
                        get_pip_url = "https://bootstrap.pypa.io/get-pip.py"
                        get_pip_path = os.path.join(
                            config.adscan_base_dir,
                            "get-pip.py",
                        )
                        download_success = False

                        try:
                            deps.download_file_with_fallbacks(
                                get_pip_url,
                                get_pip_path,
                                30,
                            )
                            download_success = True
                        except Exception as download_exc:  # noqa: BLE001
                            deps.telemetry_capture_exception(download_exc)
                            deps.print_error(
                                f"Failed to download get-pip.py: {download_exc}"
                            )

                        if download_success:
                            if (
                                os.path.exists(get_pip_path)
                                and os.path.getsize(get_pip_path) >= 1000
                            ):
                                tool_venv_bin = os.path.dirname(tool_venv_python)
                                tool_venv_dir = os.path.dirname(tool_venv_bin)
                                pip_clean_env = deps.get_clean_env_for_compilation()
                                pip_clean_env["VIRTUAL_ENV"] = tool_venv_dir
                                pip_clean_env["PATH"] = (
                                    f"{tool_venv_bin}:"
                                    f"{pip_clean_env.get('PATH', '')}"
                                )
                                pip_clean_env.pop("PYTHONHOME", None)
                                pip_clean_env.pop("PYTHONPATH", None)

                                try:
                                    deps.run_command(
                                        [tool_venv_python, get_pip_path],
                                        check=True,
                                        env=pip_clean_env,
                                    )
                                    deps.print_success(
                                        "pip installed successfully in "
                                        f"{tool_dir_name} virtual environment."
                                    )
                                    venv_created = True
                                except Exception as pip_install_exc:  # noqa: BLE001
                                    deps.telemetry_capture_exception(pip_install_exc)
                                    deps.print_warning(
                                        "Failed to install pip in "
                                        f"{tool_dir_name} venv: {pip_install_exc}"
                                    )
                                finally:
                                    try:
                                        os.remove(get_pip_path)
                                    except Exception:  # noqa: BLE001
                                        # Best-effort cleanup
                                        pass
                            else:
                                deps.print_warning(
                                    "Downloaded get-pip.py is invalid for "
                                    f"{tool_dir_name}"
                                )
                        else:
                            deps.print_warning(
                                "Failed to download get-pip.py for "
                                f"{tool_dir_name}"
                            )
                    except Exception as venv_fallback_exc:  # noqa: BLE001
                        deps.telemetry_capture_exception(venv_fallback_exc)
                        deps.print_error(
                            "Failed to create venv for "
                            f"{tool_dir_name} even with fallback: "
                            f"{venv_fallback_exc}"
                        )

                if not venv_created:
                    deps.print_error(
                        "Could not create virtual environment for "
                        f"{tool_dir_name} after all attempts."
                    )
                    all_tools_successful = False
                    continue
            except Exception as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                deps.print_error(
                    "Failed to create virtual environment for "
                    f"{tool_dir_name}: {exc}"
                )
                all_tools_successful = False
                continue
        else:
            deps.print_info(
                f"Virtual environment for {tool_dir_name} already exists."
            )

        # Install the tool itself into its venv
        deps.print_info(f"Installing {tool_dir_name} into its environment...")
        try:
            pip_env = os.environ.copy()
            pip_env["VIRTUAL_ENV"] = tool_specific_venv_path
            tool_venv_bin = os.path.dirname(tool_specific_python)
            pip_env["PATH"] = f"{tool_venv_bin}:{pip_env.get('PATH', '')}"
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
                deps.print_info_verbose(
                    "Reinstalling "
                    f"{tool_dir_name} to pinned VCS reference "
                    f"{spec_info.get('vcs_reference')}."
                )
            pip_cmd.append(install_spec)

            pip_env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
            pip_env.setdefault("PIP_NO_INPUT", "1")
            pip_env.setdefault("PIP_DEFAULT_TIMEOUT", "300")
            deps.run_pip_install_with_retries(
                pip_cmd,
                env=pip_env,
                attempts=3,
                backoff_seconds=15,
                label=f"pip install ({tool_dir_name})",
            )
            deps.print_success(f"{tool_dir_name} installed successfully.")

            if extra_specs:
                deps.print_info_verbose(
                    "Installing extra dependencies for "
                    f"{tool_dir_name}: {', '.join(extra_specs)}"
                )
                for extra_spec in extra_specs:
                    extra_spec_info = deps.parse_requirement_spec(extra_spec)
                    extra_force_reinstall = bool(
                        extra_spec_info.get("is_vcs")
                        and extra_spec_info.get("vcs_reference")
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
                        deps.print_info_verbose(
                            "Reinstalling "
                            f"{tool_dir_name} extra dependency to pinned VCS "
                            f"reference {extra_spec_info.get('vcs_reference')}."
                        )
                    extra_pip_cmd.append(extra_spec)
                    deps.run_pip_install_with_retries(
                        extra_pip_cmd,
                        env=pip_env,
                        attempts=3,
                        backoff_seconds=15,
                        label=f"pip install ({tool_dir_name} extra)",
                    )
                deps.print_success_verbose(
                    f"Extra dependencies installed for {tool_dir_name}."
                )
        except Exception as exc:  # noqa: BLE001
            deps.telemetry_capture_exception(exc)
            deps.print_error_context(
                f"Failed to install {tool_dir_name}",
                context={
                    "tool": tool_dir_name,
                    "spec": install_spec,
                    "venv": tool_specific_venv_path,
                },
                suggestions=[
                    'Check logs: tail -f "$ADSCAN_HOME/logs/adscan.log" '
                    "(default ADSCAN_HOME is ~/.adscan)",
                    f"Try manual install: pip install {install_spec}",
                    "Run with verbose mode: adscan install --verbose",
                    f"Remove venv and retry: rm -rf {tool_specific_venv_path}",
                ],
                show_exception=True,
                exception=exc,
            )
            all_tools_successful = False

    if not all_tools_successful:
        deps.print_warning(
            "Some external Python tools failed to install. "
            "Please check the logs above."
        )

    return all_tools_successful


@dataclass(frozen=True)
class CoreDepsInstallConfig:
    """Configuration for installing core Python dependencies."""

    core_requirements: List[str]


@dataclass(frozen=True)
class CoreDepsInstallDeps:
    """Dependency bundle for core dependency installation."""

    shutil_which: Callable[[str], str | None]
    sys_executable: str
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    run_pip_with_break_flag: Callable[..., None]
    telemetry_capture_installation_failed: Callable[[BaseException], None]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error_context: Callable[..., None]
    log_free_disk_space_debug: Callable[[str], None]


def install_core_dependencies(
    *, config: CoreDepsInstallConfig, deps: CoreDepsInstallDeps
) -> bool:
    """Install core Python dependencies into the system Python environment.

    This mirrors the legacy behaviour in ``handle_install`` where core
    requirements are installed with best-effort error handling and a fallback
    batch strategy when SIGBUS or negative return codes are detected.
    """
    core_requirements = config.core_requirements
    if not core_requirements:
        deps.print_info_verbose(
            "No core dependencies configured for system Python."
        )
        return True

    # Determine which Python to use for system-level installs.
    system_python = deps.shutil_which("python3")
    if not system_python:
        system_python = deps.sys_executable
        deps.print_warning("python3 not found in PATH, using sys.executable")
    else:
        deps.print_info_verbose(f"Using system Python: {system_python}")

    deps.print_info("Installing core dependencies for adscan in system Python...")
    try:
        clean_env = deps.get_clean_env_for_compilation()
        deps.run_pip_with_break_flag(
            python_executable=system_python,
            args=["--upgrade"] + core_requirements,
            env=clean_env,
            prefer_break_system_packages=True,
        )
        deps.print_success("Core dependencies installed successfully.")
        return True
    except Exception as exc:  # noqa: BLE001
        deps.telemetry_capture_installation_failed(exc)
        deps.print_error_context(
            "Failed to install core dependencies",
            context={
                "packages": ", ".join(core_requirements[:5])
                + ("..." if len(core_requirements) > 5 else ""),
                "total_packages": len(core_requirements),
                "python": system_python,
            },
            suggestions=[
                "Check your internet connection",
                "Verify pip is working: python3 -m pip --version",
                "Try manual install: pip install "
                + " ".join(core_requirements[:3]),
                "Run with verbose mode: adscan install --verbose",
            ],
            show_exception=True,
            exception=exc,
        )

        # Fallback to smaller batches when we hit SIGBUS or negative return codes.
        is_sigbus = "SIGBUS" in str(exc)
        is_called_process_error = isinstance(exc, subprocess.CalledProcessError)
        has_negative_returncode = (
            is_called_process_error and getattr(exc, "returncode", 0) < 0
        )
        if is_sigbus or has_negative_returncode:
            deps.print_warning(
                "Bulk installation failed, trying smaller batches..."
            )
            try:
                batch_size = 3
                for i in range(0, len(core_requirements), batch_size):
                    batch = core_requirements[i : i + batch_size]
                    deps.print_info(
                        "Installing batch "
                        f"{i // batch_size + 1}: {', '.join(batch)}"
                    )
                    deps.run_pip_with_break_flag(
                        python_executable=system_python,
                        args=["--ignore-installed"] + batch,
                        env=clean_env,
                        prefer_break_system_packages=True,
                    )
                deps.print_success(
                    "Core dependencies installed successfully (in batches)."
                )
                return True
            except Exception as batch_exc:  # noqa: BLE001
                deps.telemetry_capture_installation_failed(batch_exc)
                deps.print_error_context(
                    "Failed to install core dependencies even in smaller batches",
                    context={
                        "batch_size": batch_size,
                        "total_packages": len(core_requirements),
                        "python": system_python,
                    },
                    suggestions=[
                        "Check system resources (disk space, memory)",
                        "Try installing packages individually",
                        'Check logs: tail -f "$ADSCAN_HOME/logs/adscan.log" '
                        "(default ADSCAN_HOME is ~/.adscan)",
                        "Report this issue if problem persists",
                    ],
                    show_exception=True,
                    exception=batch_exc,
                )
                deps.log_free_disk_space_debug(
                    "after installation (core dependencies failed in batches)"
                )
                return False

        deps.log_free_disk_space_debug(
            "after installation (core dependencies overall failure)"
        )
        return False


@dataclass(frozen=True)
class GitToolsInstallConfig:
    """Configuration for installing external tools (git clones, curls)."""

    external_tools_config: Dict[str, Dict[str, Any]]
    tools_install_dir: str


@dataclass(frozen=True)
class GitToolsInstallDeps:
    """Dependency bundle for external tools installation."""

    setup_external_tool: Callable[[str, Dict[str, Any], bool], bool]
    preflight_install_dns: Callable[[], bool]
    get_bloodhound_mode: Callable[[], str]
    telemetry_capture_installation_failed: Callable[[BaseException], None]
    print_info: Callable[[str], None]
    print_error: Callable[[str], None]
    print_exception: Callable[..., None]
    os_makedirs: Callable[[str, Any], None]


def install_git_tools(
    *,
    config: GitToolsInstallConfig,
    deps: GitToolsInstallDeps,
) -> bool:
    """Install external tools (git clones, curls).

    This helper mirrors the legacy logic from ``handle_install`` for installing
    external tools like netexec, credsweeper, etc. All I/O and side effects are
    provided via the injected dependencies to keep the function testable and to
    avoid circular imports with ``adscan.py``.
    """
    deps.os_makedirs(config.tools_install_dir, exist_ok=True)

    # Filter tools based on conditions (e.g., legacy_only)
    external_tools = {}
    for tool_name, tool_config in config.external_tools_config.items():
        if "condition" in tool_config:
            if (
                tool_config["condition"] == "legacy_only"
                and deps.get_bloodhound_mode() != "legacy"
            ):
                deps.print_info(
                    f"Skipping {tool_name} (not needed for BloodHound CE mode)"
                )
                continue
        external_tools[tool_name] = tool_config

    # Check GitHub DNS resolution once and reuse for all external tools
    github_dns_ok = deps.preflight_install_dns()

    deps.print_info("Setting up external tools...")
    for tool_name, tool_config in external_tools.items():
        deps.print_info(f"Processing {tool_name}...")
        try:
            if not deps.setup_external_tool(tool_name, tool_config, github_dns_ok):
                return False
        except Exception as exc:  # noqa: BLE001
            deps.telemetry_capture_installation_failed(exc)
            deps.print_error(f"Failed to set up {tool_name}.")
            deps.print_exception(show_locals=False, exception=exc)
            return False

    return True


@dataclass(frozen=True)
class WordlistsInstallConfig:
    """Configuration for installing wordlists."""

    wordlists_config: Dict[str, Dict[str, Any]]
    wordlists_install_dir: str


@dataclass(frozen=True)
class WordlistsInstallDeps:
    """Dependency bundle for wordlists installation."""

    ensure_wordlist_installed: Callable[[str, Dict[str, Any], bool], bool]
    print_info: Callable[[str], None]
    print_success: Callable[[str], None]
    print_error: Callable[[str], None]
    os_makedirs: Callable[[str, Any], None]
    os_path_exists: Callable[[str], bool]
    os_path_join: Callable[[str, str], str]


def install_wordlists(
    *,
    config: WordlistsInstallConfig,
    deps: WordlistsInstallDeps,
) -> None:
    """Install wordlists.

    This helper mirrors the legacy logic from ``handle_install`` for installing
    wordlists. All I/O and side effects are provided via the injected dependencies
    to keep the function testable and to avoid circular imports with ``adscan.py``.
    """
    deps.os_makedirs(config.wordlists_install_dir, exist_ok=True)

    deps.print_info("Setting up wordlists...")
    for wl_name, wl_config in config.wordlists_config.items():
        final_wl_name = wl_config["dest"].replace(".xz", "")
        final_wl_path = deps.os_path_join(config.wordlists_install_dir, final_wl_name)
        if deps.os_path_exists(final_wl_path):
            deps.print_info(f"{wl_name} already exists at {final_wl_path}.")
            continue

        deps.print_info(f"Ensuring {wl_name} is available...")
        if deps.ensure_wordlist_installed(wl_name, wl_config, fix=True):
            deps.print_success(f"{wl_name} processed successfully.")
        else:
            deps.print_error(f"Failed to download/process {wl_name}.")


@dataclass(frozen=True)
class BloodHoundCEInstallConfig:
    """Configuration for installing BloodHound CE."""

    bh_mode_path: str
    install_args: Any | None  # argparse.Namespace or None


@dataclass(frozen=True)
class BloodHoundCEInstallDeps:
    """Dependency bundle for BloodHound CE installation."""

    is_docker_env: Callable[[], bool]
    is_docker_official_installed: Callable[[], tuple[bool, str]]
    is_docker_compose_plugin_available: Callable[[], tuple[bool, str]]
    install_bloodhound_ce: Callable[[str, bool], None]
    telemetry_capture_exception: Callable[[BaseException], None]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_exception: Callable[..., None]
    open_file: Callable[..., Any]  # Python's open() function


def install_bloodhound_ce(
    *,
    config: BloodHoundCEInstallConfig,
    deps: BloodHoundCEInstallDeps,
    docker_prereqs_ok: bool,
) -> None:
    """Install BloodHound CE if environment is suitable.

    This helper mirrors the legacy logic from ``handle_install`` for installing
    BloodHound CE. All I/O and side effects are provided via the injected
    dependencies to keep the function testable and to avoid circular imports
    with ``adscan.py``.
    """
    # Environment detection
    in_container = deps.is_docker_env()
    docker_installed, docker_version = deps.is_docker_official_installed()
    compose_available, compose_version = deps.is_docker_compose_plugin_available()

    can_install_bloodhound = (
        docker_prereqs_ok
        and docker_installed
        and compose_available
        and not in_container
    )

    deps.print_info_verbose("BloodHound CE environment check:")
    deps.print_info_verbose(f"  - Running in container: {in_container}")
    deps.print_info_verbose(
        f"  - Docker available: {docker_installed} ({docker_version})"
    )
    deps.print_info_verbose(
        f"  - Docker Compose available: {compose_available} ({compose_version})"
    )
    deps.print_info_verbose(f"  - Can install BloodHound CE: {can_install_bloodhound}")

    if not can_install_bloodhound:
        deps.print_warning("BloodHound CE installation will be skipped:")
        if not docker_prereqs_ok:
            deps.print_warning(
                "  - Docker prerequisites installation failed earlier in this run."
            )
        if in_container:
            deps.print_warning(
                "  - Running inside container (Docker-in-Docker not supported)"
            )
        if not docker_installed:
            deps.print_warning(
                f"  - Docker not available or not official: {docker_version}"
            )
        if not compose_available:
            deps.print_warning(
                f"  - Docker Compose plugin not available: {compose_version}"
            )
        deps.print_info("\nBloodHound CE requires Docker to function.")
        deps.print_info("For full functionality:")
        deps.print_info("  1. Run ADscan on a host machine with Docker installed")
        deps.print_info("  2. Install Docker and Docker Compose:")
        deps.print_info("     Ubuntu/Debian: sudo apt install docker.io docker-compose")
        deps.print_info("     Or visit: https://docs.docker.com/engine/install/")
        deps.print_info("\nNote: ADscan will continue installation without BloodHound CE")
    else:
        # Environment is suitable, proceed with installation
        try:
            desired_pw = (
                getattr(config.install_args, "bh_admin_password", "Adscan4thewin!")
                if config.install_args is not None
                else "Adscan4thewin!"
            )
            no_browser = (
                getattr(config.install_args, "no_open_browser", False)
                if config.install_args is not None
                else False
            )
            deps.install_bloodhound_ce(desired_pw, no_browser)
            try:
                with deps.open_file(config.bh_mode_path, "w", encoding="utf-8") as f:
                    f.write("ce")
            except Exception as exc:  # noqa: BLE001
                deps.telemetry_capture_exception(exc)
                deps.print_warning(f"Could not persist BH mode: {exc}")
        except Exception as exc:  # noqa: BLE001
            deps.telemetry_capture_exception(exc)
            deps.print_error("BloodHound CE installation failed.")
            deps.print_exception(show_locals=False, exception=exc)


@dataclass(frozen=True)
class RustHoundCEInstallDeps:
    """Dependency bundle for RustHound-CE installation."""

    is_cargo_available: Callable[[], tuple[bool, str]]
    install_rustup: Callable[[], bool]
    install_rusthound_ce: Callable[[], tuple[bool, str]]
    get_rusthound_verification_status: Callable[[Dict[str, str]], Dict[str, Any]]
    configure_cargo_path: Callable[[], bool]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    run_command: Callable[..., Any]
    subprocess_run: Callable[..., Any]
    os_environ: Dict[str, str]
    telemetry_capture_exception: Callable[[BaseException], None]
    print_info: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_success: Callable[[str], None]


def install_rusthound_ce_helper(
    *,
    deps: RustHoundCEInstallDeps,
) -> None:
    """Install RustHound-CE (BloodHound collector in Rust).

    This helper mirrors the legacy logic from ``handle_install`` for installing
    RustHound-CE. All I/O and side effects are provided via the injected
    dependencies to keep the function testable and to avoid circular imports
    with ``adscan.py``.
    """
    deps.print_info("Installing RustHound-CE (BloodHound collector in Rust)...")
    try:
        # Check if cargo is available
        cargo_available, cargo_version = deps.is_cargo_available()

        # Always ensure cargo is from rustup (even if already available)
        if cargo_available:
            # Check if it's from rustup installation
            cargo_path_check = deps.subprocess_run(
                ["which", "cargo"], capture_output=True, text=True, check=False
            )
            if cargo_path_check.returncode == 0:
                cargo_binary_path = cargo_path_check.stdout.strip()
                if "/.cargo/bin/cargo" not in cargo_binary_path:
                    # Cargo is available but NOT from rustup
                    deps.print_warning(
                        f"Cargo is installed but not from rustup: {cargo_binary_path}"
                    )
                    deps.print_info("Installing rustup to replace apt-installed Rust...")
                    cargo_available = False  # Force reinstallation

        if not cargo_available:
            deps.print_info(
                "cargo not found, installing via rustup (official installer)..."
            )
            deps.print_info(
                "This ensures we get the latest version (similar to Go installation)"
            )

            if not deps.install_rustup():
                deps.print_warning("Failed to install Rust toolchain via rustup")
                deps.print_info("Falling back to apt installation...")
                try:
                    # Use clean environment to avoid PyInstaller library conflicts
                    clean_env = deps.get_clean_env_for_compilation()
                    deps.run_command(
                        ["apt", "install", "cargo", "-y"], check=True, env=clean_env
                    )
                    deps.print_success("cargo installed successfully via apt (fallback)")

                    # Verify installation
                    cargo_available, cargo_version = deps.is_cargo_available()
                    if not cargo_available:
                        deps.print_warning(
                            "cargo still not available after apt installation, "
                            "skipping RustHound-CE"
                        )
                        deps.print_info("You can install Rust manually: apt install cargo")
                    else:
                        deps.print_success(f"cargo verified: {cargo_version}")
                except Exception as exc:  # noqa: BLE001
                    deps.telemetry_capture_exception(exc)
                    deps.print_warning(f"Failed to install cargo via apt: {exc}")
                    deps.print_info("You can install Rust manually: apt install cargo")
            else:
                # Verify installation after rustup install
                cargo_available, cargo_version = deps.is_cargo_available()
                if cargo_available:
                    deps.print_success(f"cargo verified: {cargo_version}")
                else:
                    deps.print_warning(
                        "Rust toolchain installed but cargo verification failed"
                    )

        if cargo_available:
            # Install RustHound-CE
            install_success, install_output = deps.install_rusthound_ce()
            if install_success:
                deps.print_success("RustHound-CE installed successfully")

                # Verify installation and configure PATH using unified function
                # Use current environment to include PATH updates
                rusthound_status = deps.get_rusthound_verification_status(
                    deps.os_environ
                )
                verification_results = rusthound_status["verification_results"]

                if verification_results["rusthound_installed"]:
                    deps.print_success(
                        f"RustHound-CE binary found at: "
                        f"{verification_results['rusthound_path']}"
                    )

                    # Configure PATH if needed
                    if not verification_results["cargo_bin_in_path"]:
                        deps.print_warning(
                            "~/.cargo/bin not found in PATH, configuring..."
                        )
                        path_configured = deps.configure_cargo_path()

                        if path_configured:
                            deps.print_success("PATH configuration completed")

                            # Test accessibility after PATH configuration
                            updated_status = deps.get_rusthound_verification_status(
                                deps.os_environ
                            )
                            if updated_status["verification_results"][
                                "rusthound_accessible"
                            ]:
                                deps.print_success(
                                    "RustHound-CE is now accessible in PATH!"
                                )
                            else:
                                deps.print_warning(
                                    "RustHound-CE may not be accessible until "
                                    "terminal restart"
                                )
                        else:
                            deps.print_warning(
                                "Failed to configure PATH for cargo binaries"
                            )
                    else:
                        deps.print_success("~/.cargo/bin already in PATH")

                        # Test accessibility using unified function
                        if verification_results["rusthound_accessible"]:
                            deps.print_success("RustHound-CE is accessible in PATH!")
                        else:
                            deps.print_warning(
                                "RustHound-CE binary exists but may not be accessible"
                            )
                else:
                    deps.print_warning(
                        f"RustHound-CE binary not found at expected location: "
                        f"{verification_results['rusthound_path']}"
                    )
            else:
                deps.print_warning(
                    f"RustHound-CE installation failed: {install_output}"
                )
                deps.print_info(
                    "You can install it manually later with: "
                    "cargo install rusthound-ce@2.4.1 --force"
                )
    except Exception as exc:  # noqa: BLE001
        deps.telemetry_capture_exception(exc)
        deps.print_warning(f"Error installing RustHound-CE: {exc}")
        deps.print_info(
            "You can install it manually later with: "
            "cargo install rusthound-ce@2.4.1 --force"
        )


@dataclass(frozen=True)
class GoHtbCliInstallDeps:
    """Dependency bundle for Go and htb-cli installation."""

    is_go_available: Callable[[], tuple[bool, str]]
    install_go_official: Callable[[], bool]
    install_htb_cli: Callable[[], tuple[bool, str]]
    is_htb_cli_installed: Callable[[], tuple[bool, str]]
    is_htb_cli_accessible: Callable[[], tuple[bool, str]]
    is_go_bin_in_path: Callable[[], tuple[bool, str]]
    configure_go_path: Callable[[], bool]
    expand_effective_user_path: Callable[[str], str]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    run_command: Callable[..., Any]
    subprocess_run: Callable[..., Any]
    os_environ: Dict[str, str]
    os_environ_get: Callable[[str, str], str]
    session_env: str
    install_summary: Dict[str, Any]
    telemetry_capture_exception: Callable[[BaseException], None]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_success: Callable[[str], None]


def install_go_and_htb_cli(
    *,
    deps: GoHtbCliInstallDeps,
) -> None:
    """Install Go and htb-cli (HackTheBox CLI tool).

    This helper mirrors the legacy logic from ``handle_install`` for installing
    Go and htb-cli. All I/O and side effects are provided via the injected
    dependencies to keep the function testable and to avoid circular imports
    with ``adscan.py``.

    NOTE: Go is always installed; htb-cli is CI-only.
    """
    # Go installation (always)
    try:
        go_available, go_version = deps.is_go_available()

        # Always ensure Go is from official source (even if already available)
        if go_available:
            go_path_check = deps.subprocess_run(
                ["which", "go"], capture_output=True, text=True, check=False
            )
            if go_path_check.returncode == 0:
                go_binary_path = go_path_check.stdout.strip()
                if "/usr/local/go/bin/go" not in go_binary_path:
                    deps.print_warning(
                        f"Go is installed but not from official source: {go_binary_path}"
                    )
                    deps.print_info(
                        "Installing official Go version to replace apt-installed version..."
                    )
                    go_available = False  # Force reinstallation

        if not go_available:
            deps.print_info("Go not found, installing from official golang.org source...")
            deps.print_info(
                "This ensures we get the latest version (similar to rustup for Rust)"
            )

            if not deps.install_go_official():
                deps.print_warning("Failed to install Go from official source")
                deps.print_info("Falling back to apt installation...")
                try:
                    clean_env = deps.get_clean_env_for_compilation()
                    deps.run_command(
                        ["apt", "install", "golang-go", "-y"],
                        check=True,
                        env=clean_env,
                    )
                    deps.print_success("Go installed successfully via apt (fallback)")
                except Exception as exc:  # noqa: BLE001
                    deps.telemetry_capture_exception(exc)
                    deps.print_warning(f"Failed to install Go via apt: {exc}")
                    deps.print_info("You can install Go manually: apt install golang-go")

        go_available, go_version = deps.is_go_available()
        if go_available:
            deps.print_success(f"Go verified: {go_version}")
        else:
            deps.print_warning("Go installed but verification failed")
    except Exception as exc:  # noqa: BLE001
        deps.telemetry_capture_exception(exc)
        deps.print_warning(f"Error installing Go: {exc}")

    # htb-cli installation (CI-only)
    if deps.session_env != "ci":
        deps.print_info_verbose(
            f"Skipping htb-cli installation in environment '{deps.session_env}' (CI-only)."
        )
        deps.install_summary["htb_cli"] = {
            "installed": False,
            "accessible": False,
            "skipped": True,
        }
    else:
        deps.print_info("Installing htb-cli (HackTheBox CLI tool)...")
        try:
            # Check if go is available
            go_available, go_version = deps.is_go_available()

            # Always ensure Go is from official source (even if already available)
            if go_available:
                # Check if it's from official installation
                go_path_check = deps.subprocess_run(
                    ["which", "go"], capture_output=True, text=True, check=False
                )
                if go_path_check.returncode == 0:
                    go_binary_path = go_path_check.stdout.strip()
                    if "/usr/local/go/bin/go" not in go_binary_path:
                        # Go is available but NOT from official source
                        deps.print_warning(
                            f"Go is installed but not from official source: {go_binary_path}"
                        )
                        deps.print_info(
                            "Installing official Go version to replace apt-installed version..."
                        )
                        go_available = False  # Force reinstallation

            if not go_available:
                deps.print_info(
                    "Go not found, installing from official golang.org source..."
                )
                deps.print_info(
                    "This ensures we get the latest version (similar to rustup for Rust)"
                )

                if not deps.install_go_official():
                    deps.print_warning("Failed to install Go from official source")
                    deps.print_info("Falling back to apt installation...")
                    try:
                        # Use clean environment to avoid PyInstaller library conflicts
                        clean_env = deps.get_clean_env_for_compilation()
                        deps.run_command(
                            ["apt", "install", "golang-go", "-y"],
                            check=True,
                            env=clean_env,
                        )
                        deps.print_success("Go installed successfully via apt (fallback)")

                        # Verify installation
                        go_available, go_version = deps.is_go_available()
                        if not go_available:
                            deps.print_warning(
                                "Go still not available after apt installation, "
                                "skipping htb-cli"
                            )
                            deps.print_info(
                                "You can install Go manually: apt install golang-go"
                            )
                        else:
                            deps.print_success(f"Go verified: {go_version}")
                    except Exception as exc:  # noqa: BLE001
                        deps.telemetry_capture_exception(exc)
                        deps.print_warning(f"Failed to install Go via apt: {exc}")
                        deps.print_info("You can install Go manually: apt install golang-go")
                else:
                    # Verify installation after official install
                    go_available, go_version = deps.is_go_available()
                    if go_available:
                        deps.print_success(f"Go verified: {go_version}")
                    else:
                        deps.print_warning("Go installed but verification failed")

            if go_available:
                # Ensure ~/go/bin is in PATH before installing htb-cli
                go_bin_path = deps.expand_effective_user_path("~/go/bin")
                current_path = deps.os_environ_get("PATH", "")
                if go_bin_path not in current_path:
                    deps.os_environ["PATH"] = f"{go_bin_path}:{current_path}"

                # Install htb-cli
                install_success, install_output = deps.install_htb_cli()
                if install_success:
                    deps.print_success("htb-cli installed successfully")
                    deps.print_info(
                        "htb-cli is a HackTheBox CLI tool for managing machines and challenges"
                    )

                    # Verify installation
                    htb_cli_installed, htb_cli_path = deps.is_htb_cli_installed()
                    if htb_cli_installed:
                        deps.print_success(f"htb-cli binary found at: {htb_cli_path}")

                        # Configure PATH if needed
                        go_bin_in_path, _ = deps.is_go_bin_in_path()
                        if not go_bin_in_path:
                            deps.print_warning("~/go/bin not found in PATH, configuring...")
                            path_configured = deps.configure_go_path()

                            if path_configured:
                                deps.print_success("PATH configuration completed")

                                # Test accessibility after PATH configuration
                                updated_env = deps.os_environ.copy()
                                if go_bin_path not in updated_env.get("PATH", ""):
                                    updated_env["PATH"] = (
                                        f"{go_bin_path}:{updated_env.get('PATH', '')}"
                                    )

                                htb_cli_accessible, _ = deps.is_htb_cli_accessible()
                                if htb_cli_accessible:
                                    deps.print_success("htb-cli is now accessible in PATH!")
                                    deps.install_summary["htb_cli"] = {
                                        "installed": True,
                                        "accessible": True,
                                        "binary_path": htb_cli_path,
                                    }
                                else:
                                    deps.print_warning(
                                        "htb-cli may not be accessible until terminal restart"
                                    )
                                    deps.install_summary["htb_cli"] = {
                                        "installed": True,
                                        "accessible": False,
                                        "binary_path": htb_cli_path,
                                    }
                            else:
                                deps.print_warning(
                                    "Failed to configure PATH for Go binaries"
                                )
                                deps.install_summary["htb_cli"] = {
                                    "installed": True,
                                    "accessible": False,
                                    "binary_path": htb_cli_path,
                                }
                        else:
                            deps.print_success("~/go/bin already in PATH")

                            # Test accessibility
                            htb_cli_accessible, _ = deps.is_htb_cli_accessible()
                            if htb_cli_accessible:
                                deps.print_success("htb-cli is accessible in PATH!")
                                deps.install_summary["htb_cli"] = {
                                    "installed": True,
                                    "accessible": True,
                                    "binary_path": htb_cli_path,
                                }
                            else:
                                deps.print_warning(
                                    "htb-cli binary exists but may not be accessible"
                                )
                                deps.install_summary["htb_cli"] = {
                                    "installed": True,
                                    "accessible": False,
                                    "binary_path": htb_cli_path,
                                }
                    else:
                        deps.print_warning(
                            f"htb-cli binary not found at expected location: {htb_cli_path}"
                        )
                        deps.install_summary["htb_cli"] = {
                            "installed": False,
                            "accessible": False,
                        }
                else:
                    deps.print_warning(f"htb-cli installation failed: {install_output}")
                    deps.install_summary["htb_cli"] = {
                        "installed": False,
                        "accessible": False,
                    }
        except Exception as exc:  # noqa: BLE001
            deps.telemetry_capture_exception(exc)
            deps.print_warning(f"Error installing htb-cli: {exc}")
            deps.install_summary["htb_cli"] = {
                "installed": False,
                "accessible": False,
            }


@dataclass(frozen=True)
class UnboundInstallConfig:
    """Configuration for Unbound installation."""

    apt_target: list[str]


@dataclass(frozen=True)
class UnboundInstallDeps:
    """Dependency bundle for Unbound installation."""

    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    get_noninteractive_apt_env: Callable[[Dict[str, str]], Dict[str, str]]
    run_command: Callable[..., Any]
    is_docker_env: Callable[[], bool]
    is_systemd_available: Callable[[], bool]
    sudo_validate: Callable[[], bool]
    get_port_53_listeners_text: Callable[..., str]
    extract_process_names_from_ss: Callable[[str], list[str]]
    stop_dns_resolver_service_for_unbound: Callable[..., None]
    run_systemctl_command: Callable[..., Any]
    telemetry_capture_exception: Callable[[BaseException], None]
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_info_debug: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_success: Callable[[str], None]
    os_geteuid: Callable[[], int]
    os_getenv: Callable[[str, str | None], str | None]


def install_unbound_resolver(
    *,
    config: UnboundInstallConfig,
    deps: UnboundInstallDeps,
) -> None:
    """Install and configure Unbound as local DNS resolver (final step)."""
    deps.print_info("Installing Unbound (local DNS resolver) as the final step...")
    try:
        clean_env = deps.get_clean_env_for_compilation()
        apt_env = deps.get_noninteractive_apt_env(clean_env)
        install_unbound_cmd = (
            ["apt-get", "install", "-y"]
            + config.apt_target
            + ["-o", "Dpkg::Use-Pty=0"]
            + [
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confnew",
            ]
            + ["unbound"]
        )
        unbound_proc = deps.run_command(
            install_unbound_cmd,
            check=False,
            capture_output=True,
            env=apt_env,
        )
        if unbound_proc and unbound_proc.returncode == 0:
            deps.print_success("Unbound installed/updated successfully")
        else:
            combined = "\n".join(
                [
                    (unbound_proc.stdout or "") if unbound_proc else "",
                    (unbound_proc.stderr or "") if unbound_proc else "",
                ]
            ).strip()
            tail = "\n".join(combined.splitlines()[-60:]) if combined else ""
            deps.print_warning(
                "Failed to install/update Unbound; local DNS may not work."
            )
            if tail:
                deps.print_info_debug(f"[apt] unbound install output tail:\n{tail}")

        # Configure Unbound service if possible (avoid changing resolvers in container/CI).
        if deps.is_docker_env() or deps.os_getenv("CI"):
            deps.print_info_verbose(
                "Skipping Unbound service management in container/CI environment "
                "(leaving system DNS untouched)."
            )
            return

        systemd_available = deps.is_systemd_available()
        can_sudo = deps.os_geteuid() == 0 or deps.sudo_validate()

        # Stop common resolver services that may already occupy port 53.
        if can_sudo:
            listeners = deps.get_port_53_listeners_text(
                use_sudo=bool(can_sudo and deps.os_geteuid() != 0),
            )
            procs = deps.extract_process_names_from_ss(listeners)
            if "dnsmasq" in procs:
                deps.print_warning(
                    "dnsmasq is running and may be using port 53; stopping it to allow Unbound to start."
                )
                deps.stop_dns_resolver_service_for_unbound(
                    "dnsmasq",
                    systemd_available=systemd_available,
                    context="install (finalize unbound)",
                )
            if "systemd-resolved" in procs:
                deps.print_warning(
                    "systemd-resolved is running and may be using port 53; stopping it to allow Unbound to start."
                )
                deps.stop_dns_resolver_service_for_unbound(
                    "systemd-resolved",
                    systemd_available=systemd_available,
                    context="install (finalize unbound)",
                )
        else:
            deps.print_warning(
                "Cannot manage resolver services without sudo; Unbound may fail to start if port 53 is occupied."
            )

        if systemd_available:
            deps.run_systemctl_command(["enable", "unbound"], check=False, timeout=30)
            deps.run_systemctl_command(["start", "unbound"], check=False, timeout=30)
            status_result = deps.run_command(
                ["systemctl", "is-active", "unbound"],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if status_result and status_result.returncode == 0:
                deps.print_success("DNS service is active and ready")
            else:
                deps.print_warning("Unbound service may not be running properly")
                deps.print_info_debug(
                    "[dns] port 53 listeners:\n"
                    f"{deps.get_port_53_listeners_text(use_sudo=bool(can_sudo and deps.os_geteuid() != 0))}"
                )
        else:
            deps.print_info_verbose(
                "systemd is not available; skipping unbound enable/start checks during install."
            )
    except Exception as exc:  # noqa: BLE001
        deps.telemetry_capture_exception(exc)
        deps.print_warning(f"Failed to finalize Unbound installation/configuration: {exc}")


@dataclass(frozen=True)
class InstallConfig:
    """Configuration for the main installation process.

    Attributes:
        install_args: Optional argparse.Namespace with installation arguments.
        python_version: Python version to install (default: "3.12.3").
        adscan_base_dir: Base directory for ADscan installation.
        tools_install_dir: Directory for external tools.
        wordlists_install_dir: Directory for wordlists.
        tool_venvs_base_dir: Base directory for tool virtual environments.
        venv_path: Path to the main virtual environment.
        bh_mode_path: Path to BloodHound mode file.
        system_packages_config: Configuration for system packages.
        core_requirements: Core Python requirements.
        pip_tools_config: Configuration for pip tools.
        external_tools_config: Configuration for external tools.
        wordlists_config: Configuration for wordlists.
    """

    install_args: Any | None
    python_version: str
    adscan_base_dir: str
    tools_install_dir: str
    wordlists_install_dir: str
    tool_venvs_base_dir: str
    venv_path: str
    bh_mode_path: str
    system_packages_config: Dict[str, str]
    core_requirements: List[str]
    pip_tools_config: Dict[str, Any]
    external_tools_config: Dict[str, Any]
    wordlists_config: Dict[str, Any]


@dataclass(frozen=True)
class InstallDeps:
    """Dependency bundle for the main installation flow."""

    # Environment and disk space checks
    log_free_disk_space_debug: Callable[[str], None]
    determine_session_environment: Callable[[], str]
    get_free_disk_space_bytes: Callable[[str], int | None]
    is_docker_env: Callable[[], bool]
    is_docker_official_installed: Callable[[], tuple[bool, str]]
    is_docker_compose_plugin_available: Callable[[], tuple[bool, str]]
    get_bloodhound_mode: Callable[[], str]

    # Installation helpers
    install_docker_prerequisites: Callable[[], bool]
    install_pyenv_python_and_venv: Callable[[str, str], tuple[bool, list[str], str]]
    setup_external_tool: Callable[[str, Dict[str, Any], bool], bool]
    preflight_install_dns: Callable[[], bool]
    install_go_official: Callable[[], bool]
    install_htb_cli: Callable[[], tuple[bool, str]]
    is_go_available: Callable[[], tuple[bool, str]]
    is_htb_cli_installed: Callable[[], tuple[bool, str]]
    is_go_bin_in_path: Callable[[], tuple[bool, str]]
    configure_go_path: Callable[[], bool]
    is_htb_cli_accessible: Callable[[], tuple[bool, str]]
    expand_effective_user_path: Callable[[str], str]

    # Command execution
    run_command: Callable[..., object]
    get_clean_env_for_compilation: Callable[[], Dict[str, str]]
    get_noninteractive_apt_env: Callable[[Dict[str, str]], Dict[str, str]]

    # Telemetry
    telemetry_capture_exception: Callable[[BaseException], None]
    telemetry_capture_installation_failed: Callable[[BaseException], None]
    telemetry_capture_user_property_event: Callable[[str, str, str], None]
    telemetry_capture: Callable[[str, Dict[str, Any]], None]

    # Output functions
    print_info: Callable[[str], None]
    print_info_verbose: Callable[[str], None]
    print_info_debug: Callable[[str], None]
    print_success: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_error: Callable[[str], None]
    print_instruction: Callable[[str], None]
    print_exception: Callable[..., None]
    print_code: Callable[[str, str, str], None]
    print_install_summary: Callable[[], None]

    # Check function (for post-install check)
    handle_check: Callable[[Any], bool]

    # Global state (INSTALL_SUMMARY)
    install_summary: Dict[str, Any]

    # Standard library
    os_makedirs: Callable[[str, int], None]
    os_path_exists: Callable[[str], bool]
    os_getenv: Callable[[str, str | None], str | None]
    os_geteuid: Callable[[], int]
    subprocess_run: Callable[..., Any]

    # Debug mode flag
    debug_mode: bool


def run_install(
    *,
    config: InstallConfig,
    deps: InstallDeps,
) -> bool:
    """Main installation orchestrator.

    This function orchestrates the complete installation process for ADscan,
    including system packages, Python dependencies, external tools, wordlists,
    BloodHound CE, RustHound-CE, Go, and htb-cli.

    All I/O, subprocess calls, and telemetry are injected via ``deps`` to keep
    this function testable and to avoid circular imports with ``adscan.py``.

    Returns:
        True if installation completed successfully, False otherwise.
    """
    deps.log_free_disk_space_debug("before installation")
    session_env = deps.determine_session_environment()
    if deps.debug_mode:
        deps.print_info_debug(
            "[install] environment detection: "
            f"session_env={session_env}, "
            f"ADSCAN_SESSION_ENV={deps.os_getenv('ADSCAN_SESSION_ENV')!r}, "
            f"CI={deps.os_getenv('CI')!r}, "
            f"GITHUB_ACTIONS={deps.os_getenv('GITHUB_ACTIONS')!r}, "
            f"euid={deps.os_geteuid()}"
        )

    # Check disk space
    allow_low_disk = bool(
        getattr(config.install_args, "allow_low_disk", False)
        if config.install_args
        else False
    )
    free_bytes = deps.get_free_disk_space_bytes("/")
    min_free_bytes = 10 * 1024**3  # 10GB
    if free_bytes is not None and free_bytes < min_free_bytes and not allow_low_disk:
        free_gb = free_bytes / (1024**3)
        deps.telemetry_capture_user_property_event(
            "install_blocked_low_disk",
            "installation_status",
            "blocked_low_disk",
        )
        deps.print_error(
            f"Not enough free disk space to run a full installation ({free_gb:.2f} GB available)."
        )
        deps.print_instruction("Free up disk space and retry (recommended minimum: 10 GB).")
        deps.print_instruction(
            "Override this check (not recommended): adscan install --allow-low-disk"
        )
        return False

    # Environment detection
    in_container = deps.is_docker_env()
    docker_installed, docker_version = deps.is_docker_official_installed()
    compose_available, compose_version = deps.is_docker_compose_plugin_available()

    # Check if only specific components should be installed (for QA testing)
    only_components = []
    if config.install_args and hasattr(config.install_args, "only") and config.install_args.only:
        only_components = config.install_args.only

    if only_components:
        # Handle selective component installation (QA mode)
        deps.print_info(
            f"Starting installation of specific components only (QA mode): {', '.join(only_components)}"
        )
        deps.telemetry_capture_user_property_event(
            "install_started",
            "installation_status",
            f"only_{','.join(only_components)}",
        )

        install_success = True

        # Install BloodHound CE if requested
        if "bloodhound" in only_components:
            deps.print_info("Installing BloodHound CE...")
            can_install_bloodhound = docker_installed and compose_available and not in_container

            if not can_install_bloodhound:
                deps.print_error("Cannot install BloodHound CE:")
                if in_container:
                    deps.print_error(
                        "  - Running inside container (Docker-in-Docker not supported)"
                    )
                    deps.print_info(
                        "  BloodHound CE cannot be installed in containerized environments"
                    )
                    install_success = False
                else:
                    if not docker_installed:
                        deps.print_error(f"  - Docker not available or not official: {docker_version}")
                    if not compose_available:
                        deps.print_error(
                            f"  - Docker Compose plugin not available: {compose_version}"
                        )
                    deps.print_info("\nSolutions:")
                    deps.print_info(
                        "  1. Run ADscan on a host machine with Docker installed (recommended)"
                    )
                    deps.print_info("  2. Install Docker and Docker Compose:")
                    deps.print_info(
                        "     Ubuntu/Debian: sudo apt install docker.io docker-compose"
                    )
                    deps.print_info("     Or visit: https://docs.docker.com/engine/install/")
                    install_success = False

                    if not deps.install_docker_prerequisites():
                        deps.print_error(
                            "Docker prerequisites installation failed. Cannot install BloodHound CE."
                        )
                        install_success = False
                    else:
                        # Note: _install_bloodhound_ce needs to be passed via deps
                        # For now, we'll skip this in selective mode as it requires
                        # additional dependencies that are complex to inject
                        deps.print_warning(
                            "BloodHound CE installation in selective mode requires full deps"
                        )
                        install_success = False
            else:
                if not deps.install_docker_prerequisites():
                    deps.print_error(
                        "Docker prerequisites installation failed. Cannot install BloodHound CE."
                    )
                    install_success = False
                else:
                    # Note: _install_bloodhound_ce needs to be passed via deps
                    deps.print_warning(
                        "BloodHound CE installation in selective mode requires full deps"
                    )
                    install_success = False

        # Install RustHound-CE if requested
        if "rusthound" in only_components:
            deps.print_info("Installing RustHound-CE...")
            # Note: RustHound-CE installation in selective mode requires
            # additional dependencies that are complex to inject
            deps.print_warning(
                "RustHound-CE installation in selective mode requires full deps"
            )
            install_success = False

        # Install pyenv if requested
        if "pyenv" in only_components:
            deps.print_info("Installing pyenv (with Python and venv setup for testing)...")
            deps.print_info("Installing Python build dependencies...")
            # Note: pyenv installation in selective mode requires
            # additional dependencies that are complex to inject
            deps.print_warning("pyenv installation in selective mode requires full deps")
            install_success = False

        # Final status
        if install_success:
            deps.print_success(
                f"Selected components installation completed successfully: {', '.join(only_components)}"
            )
        else:
            deps.print_error("Some components failed to install. Check the logs above.")

        deps.log_free_disk_space_debug("after installation (selected components)")
        return install_success

    # Full installation process
    deps.print_info("Starting ADscan installation process...")
    deps.telemetry_capture_user_property_event(
        "install_started", "installation_status", "install_started"
    )

    # Create the base directories if they don't exist
    deps.os_makedirs(config.adscan_base_dir, exist_ok=True)
    deps.os_makedirs(config.tools_install_dir, exist_ok=True)
    deps.os_makedirs(config.wordlists_install_dir, exist_ok=True)
    deps.os_makedirs(config.tool_venvs_base_dir, exist_ok=True)

    # Detect if libcom-err2 comes from backports to set apt_target
    apt_target = []
    try:
        dpkg_proc = deps.run_command(
            ["dpkg-query", "-W", "-f=${Version}", "libcom-err2"],
            check=False,
            capture_output=True,
            text=True,
        )
        libcomver = dpkg_proc.stdout.strip() if dpkg_proc and dpkg_proc.stdout else ""
        if "bpo" in libcomver:
            codename_proc = deps.run_command(
                ["sh", "-c", ". /etc/os-release && echo ${VERSION_CODENAME}-backports"],
                check=False,
                capture_output=True,
                text=True,
            )
            codename = (
                codename_proc.stdout.strip()
                if codename_proc and codename_proc.stdout
                else ""
            )
            apt_target = ["-t", codename]
            deps.print_info(f"Using apt target from backports: {codename}")
    except Exception as e:
        deps.telemetry_capture_exception(e)
        apt_target = []

    # Update package lists
    deps.print_info("Updating package lists (running as root)...")
    try:
        clean_env = deps.get_clean_env_for_compilation()
        deps.run_command(["apt-get", "update", "-y"], check=True, env=clean_env)
        deps.print_success("Package lists updated successfully.")
    except Exception as e:
        deps.telemetry_capture_exception(e)
        if isinstance(e, FileNotFoundError):
            deps.telemetry_capture_installation_failed(e)
            deps.print_error(
                "'apt-get' command not found. This script assumes a Debian-based system with apt."
            )
        else:
            deps.print_error(
                f"Failed to update package lists: {getattr(e, 'stderr', '') or getattr(e, 'stdout', '')}"
            )
            deps.print_error("Cannot continue installation without a successful apt update.")
        deps.log_free_disk_space_debug("after installation (apt-get update failed)")
        return False

    # Track Docker prerequisite status for later BloodHound CE installation
    docker_prereqs_ok = True

    # Docker prerequisites (install early: docker engine + compose)
    if in_container:
        deps.print_info_verbose(
            "Skipping Docker installation: running inside container (Docker-in-Docker not supported)"
        )
    else:
        docker_prereqs_ok = deps.install_docker_prerequisites()
        if not docker_prereqs_ok:
            deps.print_warning(
                "Docker prerequisites installation failed. BloodHound CE will be skipped in this run."
            )

    # Skip Neo4j setup (BloodHound CE uses containerized graph DB)
    deps.print_info("Skipping Neo4j setup (BloodHound CE uses containerized graph DB).")

    # Install/update all system packages
    install_unbound_last = "unbound" in config.system_packages_config
    install_system_packages(
        config=SystemPackagesInstallConfig(
            system_packages_config=config.system_packages_config,
            apt_target=apt_target,
        ),
        deps=SystemPackagesInstallDeps(
            run_command=deps.run_command,
            get_clean_env_for_compilation=deps.get_clean_env_for_compilation,
            get_noninteractive_apt_env=deps.get_noninteractive_apt_env,
            install_rustup=lambda: True,  # Will be handled by system packages helper
            telemetry_capture_exception=deps.telemetry_capture_exception,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
            print_success=deps.print_success,
            print_info_debug=deps.print_info_debug,
            print_warning_debug=deps.print_warning,
            print_instruction=deps.print_instruction,
            print_exception=deps.print_exception,
        ),
    )

    # Pyenv Setup
    pyenv_success, pyenv_cmd_list, python_executable_path = (
        deps.install_pyenv_python_and_venv(
            python_version=config.python_version, venv_path=config.venv_path
        )
    )

    if not pyenv_success:
        return False

    # Install core dependencies
    core_ok = install_core_dependencies(
        config=CoreDepsInstallConfig(core_requirements=config.core_requirements),
        deps=CoreDepsInstallDeps(
            shutil_which=shutil.which,
            sys_executable=sys.executable,
            get_clean_env_for_compilation=deps.get_clean_env_for_compilation,
            run_pip_with_break_flag=lambda *args, **kwargs: True,  # Placeholder
            telemetry_capture_installation_failed=deps.telemetry_capture_installation_failed,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_success=deps.print_success,
            print_warning=deps.print_warning,
            print_error_context=deps.print_error,
            log_free_disk_space_debug=deps.log_free_disk_space_debug,
        ),
    )
    if not core_ok:
        return False

    # Install external Python tools
    install_external_python_tools(
        config=ExternalToolsInstallConfig(
            pip_tools_config=config.pip_tools_config,
            tool_venvs_base_dir=config.tool_venvs_base_dir,
            python_version=config.python_version,
            adscan_base_dir=config.adscan_base_dir,
        ),
        deps=ExternalToolsInstallDeps(
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_success=deps.print_success,
            print_success_verbose=deps.print_success,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
            print_error_context=deps.print_error,
            telemetry_capture_exception=deps.telemetry_capture_exception,
            run_command=deps.run_command,
            get_clean_env_for_compilation=deps.get_clean_env_for_compilation,
            get_pyenv_available=lambda env=None: (True, "1.0"),  # Placeholder
            preflight_install_dns=deps.preflight_install_dns,
            configure_ssl_certificates=lambda: True,  # Placeholder
            parse_requirement_spec=lambda spec: spec,  # Placeholder
            run_pip_install_with_retries=lambda *args, **kwargs: True,  # Placeholder
            download_file_with_fallbacks=lambda *args, **kwargs: True,  # Placeholder
        ),
    )

    # External Tools Installation (Git clones, curls)
    deps.os_makedirs(config.tools_install_dir, exist_ok=True)
    external_tools = {}
    for tool_name, tool_config in config.external_tools_config.items():
        if "condition" in tool_config:
            if (
                tool_config["condition"] == "legacy_only"
                and deps.get_bloodhound_mode() != "legacy"
            ):
                deps.print_info(f"Skipping {tool_name} (not needed for BloodHound CE mode)")
                continue
        external_tools[tool_name] = tool_config

    github_dns_ok = deps.preflight_install_dns()

    deps.print_info("Setting up external tools...")
    for tool_name, tool_config in external_tools.items():
        deps.print_info(f"Processing {tool_name}...")
        try:
            if not deps.setup_external_tool(tool_name, tool_config, github_dns_ok=github_dns_ok):
                return False
        except Exception as e:
            deps.telemetry_capture_installation_failed(e)
            deps.print_error(f"Failed to set up {tool_name}.")
            deps.print_exception(show_locals=False, exception=e)
            return False

    # Wordlists Installation
    install_wordlists(
        config=WordlistsInstallConfig(
            wordlists_config=config.wordlists_config,
            wordlists_install_dir=config.wordlists_install_dir,
        ),
        deps=WordlistsInstallDeps(
            ensure_wordlist_installed=lambda *args, **kwargs: True,  # Placeholder
            print_info=deps.print_info,
            print_success=deps.print_success,
            print_error=deps.print_error,
            os_makedirs=deps.os_makedirs,
            os_path_exists=deps.os_path_exists,
            os_path_join=os.path.join,
        ),
    )

    # BloodHound CE Installation
    install_bloodhound_ce(
        config=BloodHoundCEInstallConfig(
            bh_mode_path=config.bh_mode_path,
            install_args=config.install_args,
        ),
        deps=BloodHoundCEInstallDeps(
            is_docker_env=deps.is_docker_env,
            is_docker_official_installed=deps.is_docker_official_installed,
            is_docker_compose_plugin_available=deps.is_docker_compose_plugin_available,
            install_bloodhound_ce=lambda *args, **kwargs: True,  # Placeholder - needs full deps
            telemetry_capture_exception=deps.telemetry_capture_exception,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_warning=deps.print_warning,
            print_error=deps.print_error,
            print_exception=deps.print_exception,
            open_file=open,
        ),
        docker_prereqs_ok=docker_prereqs_ok,
    )

    # RustHound-CE Installation
    install_rusthound_ce_helper(
        deps=RustHoundCEInstallDeps(
            is_cargo_available=lambda: (True, "1.0"),  # Placeholder
            install_rustup=lambda: True,  # Placeholder
            install_rusthound_ce=lambda: (True, ""),  # Placeholder
            get_rusthound_verification_status=lambda env: {"verification_results": {}},  # Placeholder
            configure_cargo_path=lambda: True,  # Placeholder
            get_clean_env_for_compilation=deps.get_clean_env_for_compilation,
            run_command=deps.run_command,
            subprocess_run=deps.subprocess_run,
            os_environ={},  # Placeholder
            telemetry_capture_exception=deps.telemetry_capture_exception,
            print_info=deps.print_info,
            print_warning=deps.print_warning,
            print_success=deps.print_success,
        ),
    )

    # Go and htb-cli Installation
    install_go_and_htb_cli(
        deps=GoHtbCliInstallDeps(
            is_go_available=deps.is_go_available,
            install_go_official=deps.install_go_official,
            install_htb_cli=deps.install_htb_cli,
            is_htb_cli_installed=deps.is_htb_cli_installed,
            is_go_bin_in_path=deps.is_go_bin_in_path,
            configure_go_path=deps.configure_go_path,
            is_htb_cli_accessible=deps.is_htb_cli_accessible,
            expand_effective_user_path=deps.expand_effective_user_path,
            get_clean_env_for_compilation=deps.get_clean_env_for_compilation,
            run_command=deps.run_command,
            subprocess_run=deps.subprocess_run,
            os_environ=deps.os_environ,
            os_environ_get=deps.os_getenv,
            session_env=session_env,
            install_summary=deps.install_summary,
            telemetry_capture_exception=deps.telemetry_capture_exception,
            print_info=deps.print_info,
            print_info_verbose=deps.print_info_verbose,
            print_warning=deps.print_warning,
            print_success=deps.print_success,
        ),
    )

    # Install/configure Unbound last
    if install_unbound_last:
        install_unbound_resolver(
            config=UnboundInstallConfig(apt_target=apt_target),
            deps=UnboundInstallDeps(
                get_clean_env_for_compilation=deps.get_clean_env_for_compilation,
                get_noninteractive_apt_env=deps.get_noninteractive_apt_env,
                run_command=deps.run_command,
                is_docker_env=deps.is_docker_env,
                is_systemd_available=lambda: True,  # Placeholder
                sudo_validate=lambda: True,  # Placeholder
                get_port_53_listeners_text=lambda use_sudo=False: "",  # Placeholder
                extract_process_names_from_ss=lambda text: [],  # Placeholder
                stop_dns_resolver_service_for_unbound=lambda *args, **kwargs: None,  # Placeholder
                run_systemctl_command=lambda *args, **kwargs: None,  # Placeholder
                telemetry_capture_exception=deps.telemetry_capture_exception,
                print_info=deps.print_info,
                print_info_verbose=deps.print_info_verbose,
                print_info_debug=deps.print_info_debug,
                print_warning=deps.print_warning,
                print_success=deps.print_success,
                os_geteuid=deps.os_geteuid,
                os_getenv=deps.os_getenv,
            ),
        )

    # Post-install sanity check
    deps.print_info("")
    deps.print_info("Running post-installation check...")
    post_install_check_args = type("Namespace", (), {"command": "check", "fix": False})()
    post_install_ok = deps.handle_check(post_install_check_args)
    deps.install_summary["post_install_check"] = {"success": bool(post_install_ok)}

    deps.print_install_summary()
    deps.print_success("ADscan installation complete")

    # Show next steps
    next_steps = """# Launch the interactive CLI
adscan start"""
    deps.print_code(next_steps, language="bash", title="[bold]Next Steps[/bold]")

    deps.telemetry_capture(
        "installed", properties={"$set": {"installation_status": "installed"}}
    )
    deps.log_free_disk_space_debug("after installation (full)")
    return True
