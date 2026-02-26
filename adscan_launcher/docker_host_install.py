"""Host Docker installation helpers for legacy install mode.

This module contains the host-based Docker installation logic that used to live
in `adscan.py`. It is responsible for:
- Detecting the Linux distribution/codename for Docker's APT repository
- Removing old/unofficial Docker packages
- Adding Docker's official GPG key and repository
- Installing Docker Engine and the Docker Compose plugin from the official repo
"""

from __future__ import annotations

import os
import subprocess
import traceback
from typing import Dict

from adscan_core.subprocess_env import get_clean_env_for_compilation
from adscan_launcher import telemetry
from adscan_launcher.docker_runtime import is_docker_env
from adscan_launcher.docker_status import (
    is_docker_compose_plugin_available,
    is_official_docker_installed,
)
from adscan_launcher.output import (
    print_error,
    print_exception,
    print_info,
    print_info_verbose,
    print_success,
    print_warning,
)


def _detect_distribution() -> Dict[str, str | None]:
    """Detect Linux distribution and version for Docker repository setup."""
    distro_info: Dict[str, str | None] = {
        "id": None,
        "id_like": None,
        "pretty_name": None,
        "version_id": None,
        "version_codename": None,
        "base_distro": None,  # 'ubuntu', 'debian', or None
    }

    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            os_release: Dict[str, str] = {}
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    value = value.strip('"').strip("'")
                    os_release[key] = value

        distro_id = os_release.get("ID", "").lower()
        version_codename = os_release.get("VERSION_CODENAME") or os_release.get(
            "UBUNTU_CODENAME"
        )
        id_like = os_release.get("ID_LIKE", "").lower()
        pretty_name = os_release.get("PRETTY_NAME", "").lower()
        version_id = os_release.get("VERSION_ID", "") or ""

        distro_info["id_like"] = id_like
        distro_info["pretty_name"] = pretty_name
        distro_info["version_id"] = version_id

        if "parrot" in distro_id or "parrot" in id_like or "parrot" in pretty_name:
            distro_info["id"] = "parrot"
            distro_info["base_distro"] = "debian"
        elif "kali" in distro_id or "kali" in id_like or "kali" in pretty_name:
            distro_info["id"] = "kali"
            distro_info["base_distro"] = "debian"
        elif distro_id in ["ubuntu", "kubuntu", "lubuntu", "xubuntu"]:
            distro_info["id"] = distro_id
            distro_info["base_distro"] = "ubuntu"
        elif distro_id == "debian":
            distro_info["id"] = "debian"
            distro_info["base_distro"] = "debian"
        else:
            distro_info["id"] = distro_id
            distro_info["base_distro"] = "debian"

        distro_info["version_codename"] = version_codename
        return distro_info

    except (OSError, IOError, FileNotFoundError, KeyError, ValueError) as exc:
        telemetry.capture_exception(exc)
        return {
            "id": "debian",
            "id_like": "debian",
            "pretty_name": "debian",
            "version_id": None,
            "version_codename": None,
            "base_distro": "debian",
        }


def _get_debian_base_version(distro_id: str, version_codename: str | None) -> str:
    """Get Debian base version codename for Debian-based distributions."""
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            os_release: Dict[str, str] = {}
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    value = value.strip('"').strip("'")
                    os_release[key] = value

        debian_codename = os_release.get("DEBIAN_CODENAME", "")
        if debian_codename:
            print_info_verbose(
                f"Found DEBIAN_CODENAME in /etc/os-release: {debian_codename}"
            )
            return debian_codename

        print_info_verbose("[bold]Distribution detection[/bold]")
        print_info_verbose(
            f"ID={distro_id}, VERSION_CODENAME={version_codename or 'N/A'}, "
            f"VERSION_ID={os_release.get('VERSION_ID', 'N/A')}"
        )

        if distro_id == "parrot" and version_codename == "lory":
            print_info_verbose(
                "Mapped Parrot 'lory' -> Debian 'bookworm' (Parrot 6.x -> Debian 12)"
            )
            return "bookworm"

        print_info_verbose("No DEBIAN_CODENAME found, parsing /etc/debian_version...")

        with open("/etc/debian_version", "r", encoding="utf-8") as f:
            debian_version = f.read().strip()

        print_info_verbose(f"Read /etc/debian_version: '{debian_version}'")

        token = debian_version.split("/")[0].split()[0]

        if token and token.split(".")[0].isdigit():
            major_version = int(token.split(".")[0])
            version_to_codename = {
                13: "trixie",
                12: "bookworm",
                11: "bullseye",
                10: "buster",
            }
            debian_codename = version_to_codename.get(major_version)
            if debian_codename:
                return debian_codename

        if token:
            return token

    except Exception as exc:  # pragma: no cover
        telemetry.capture_exception(exc)

    return "bookworm"


def _remove_old_docker_packages() -> bool:
    """Remove old Docker packages from unofficial repositories."""
    try:
        print_info(
            "[bold]Removing old Docker packages[/bold] from unofficial repositories..."
        )

        packages_to_remove = [
            "docker.io",
            "docker-doc",
            "docker-compose",
            "docker-compose-v2",
            "docker-cli",
            "docker-buildx",
            "docker-buildx-plugin",
            "docker-compose-plugin",
            "podman-docker",
            "containerd",
            "runc",
        ]

        installed_packages: list[str] = []
        for pkg in packages_to_remove:
            result = subprocess.run(
                ["dpkg", "-l", pkg],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout and "ii" in result.stdout:
                installed_packages.append(pkg)

        if not installed_packages:
            print_info("[dim]No old Docker packages found to remove.[/dim]")
            return True

        print_info(f"[bold]Removing packages:[/bold] {', '.join(installed_packages)}")
        subprocess.run(["apt-get", "remove", "-y"] + installed_packages, check=False)
        print_success(
            "[bold]Old Docker packages[/bold] removed",
            items=[f"[dim]{pkg}[/dim]" for pkg in installed_packages],
            panel=True,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("Failed to remove old Docker packages.")
        print_exception(show_locals=False, exception=exc)
        return True


def _add_docker_gpg_key() -> bool:
    """Add Docker's official GPG key."""
    try:
        print_info("[bold]Adding Docker's official GPG key[/bold]...")

        clean_env = get_clean_env_for_compilation()
        subprocess.run(["apt-get", "update"], check=True, env=clean_env)
        subprocess.run(
            ["apt-get", "install", "-y", "ca-certificates", "curl"],
            check=True,
            env=clean_env,
        )

        os.makedirs("/etc/apt/keyrings", mode=0o755, exist_ok=True)

        distro_info = _detect_distribution()
        base_distro = distro_info.get("base_distro")

        if base_distro == "ubuntu":
            gpg_key_url = "https://download.docker.com/linux/ubuntu/gpg"
        else:
            gpg_key_url = "https://download.docker.com/linux/debian/gpg"

        gpg_key_path = "/etc/apt/keyrings/docker.asc"

        subprocess.run(
            ["curl", "-fsSL", gpg_key_url, "-o", gpg_key_path],
            check=True,
        )

        os.chmod(gpg_key_path, 0o644)

        print_success(
            "[bold]Docker GPG key[/bold] added successfully",
            items=[
                f"[cyan]Source:[/cyan] {gpg_key_url}",
                f"[cyan]Path:[/cyan] {gpg_key_path}",
            ],
            panel=True,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Failed to add Docker GPG key.")
        print_exception(show_locals=False, exception=exc)
        return False


def _add_docker_repository() -> bool:
    """Add Docker's official APT repository."""
    try:
        print_info("[bold]Adding Docker's official APT repository[/bold]...")

        distro_info = _detect_distribution()
        distro_id = (distro_info.get("id") or "").lower()
        base_distro = (distro_info.get("base_distro") or "").lower()
        version_codename = distro_info.get("version_codename")

        if base_distro not in {"debian", "ubuntu"}:
            print_warning(
                f"Unsupported base distribution '{base_distro}'. "
                "Docker's official repository may not be available."
            )

        if base_distro == "ubuntu":
            repo_codename = version_codename or "jammy"
            repo_url = (
                "deb [arch=$(dpkg --print-architecture) "
                "signed-by=/etc/apt/keyrings/docker.asc] "
                f"https://download.docker.com/linux/ubuntu {repo_codename} stable"
            )
        else:
            debian_codename = _get_debian_base_version(distro_id, version_codename)
            repo_url = (
                "deb [arch=$(dpkg --print-architecture) "
                "signed-by=/etc/apt/keyrings/docker.asc] "
                f"https://download.docker.com/linux/debian {debian_codename} stable"
            )

        os.makedirs("/etc/apt/sources.list.d", mode=0o755, exist_ok=True)
        repo_file_path = "/etc/apt/sources.list.d/docker.list"

        with open(repo_file_path, "w", encoding="utf-8") as repo_file:
            repo_file.write(repo_url + "\n")

        print_success(
            "[bold]Docker repository[/bold] configured successfully",
            items=[
                f"[cyan]Distribution:[/cyan] {distro_id}",
                f"[cyan]Repo file:[/cyan] {repo_file_path}",
            ],
            panel=True,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Failed to add Docker repository.")
        print_exception(show_locals=False, exception=exc)
        tb = traceback.format_exc()
        if tb:
            print_info_verbose(f"Traceback while adding Docker repo:\n{tb}")
        return False


def install_docker_prerequisites() -> bool:
    """Install Docker Engine and Docker Compose plugin using official repositories.

    This is a host-only helper; when running inside a Docker container, it
    performs detection only and does not attempt to install packages.
    """
    try:
        in_container = is_docker_env()
        if in_container:
            print_info_verbose(
                "Skipping Docker installation: running inside container "
                "(Docker-in-Docker not supported)"
            )
            docker_installed, docker_version = is_official_docker_installed()
            compose_available, compose_version = is_docker_compose_plugin_available()
            if docker_installed and compose_available:
                print_info_verbose(
                    "Docker and Compose available via host: "
                    f"Docker {docker_version}, Compose {compose_version}"
                )
                return True
            return True

        docker_installed, docker_version = is_official_docker_installed()
        compose_available, compose_version = is_docker_compose_plugin_available()

        if docker_installed and compose_available:
            print_success(
                "[bold]Docker and Docker Compose[/bold] already present",
                items=[
                    f"[cyan]Docker:[/cyan] {docker_version}",
                    f"[cyan]Docker Compose:[/cyan] {compose_version}",
                ],
                panel=True,
            )
            return True
        if docker_installed and not compose_available:
            print_warning(
                f"Official Docker found ({docker_version}) but Docker Compose plugin missing."
            )
            print_info("Will install Docker Compose plugin...")
        elif not docker_installed and compose_available:
            print_warning(
                f"Docker Compose plugin found ({compose_version}) but official Docker missing."
            )
            print_info("Will install official Docker Engine...")
        else:
            print_info("Neither official Docker nor Docker Compose plugin found.")
            print_info("Will install both from official repositories...")

        print_info(
            "Installing Docker engine and Docker Compose from official repositories..."
        )

        if not _remove_old_docker_packages():
            print_warning("Failed to remove old Docker packages, continuing anyway...")

        if not _add_docker_gpg_key():
            print_error("Failed to add Docker GPG key")
            return False

        if not _add_docker_repository():
            print_error("Failed to add Docker repository")
            return False

        print_info(
            "[bold]Updating package list[/bold] after adding Docker repository..."
        )
        clean_env = get_clean_env_for_compilation()
        subprocess.run(["apt-get", "update"], check=True, env=clean_env)
        print_success("[bold]Package list[/bold] updated successfully", panel=True)

        print_info("[bold]Installing Docker Engine and Docker Compose plugin[/bold]...")
        docker_packages = [
            "docker-ce",
            "docker-ce-cli",
            "containerd.io",
            "docker-buildx-plugin",
            "docker-compose-plugin",
        ]
        docker_install_result = subprocess.run(
            ["apt-get", "install", "-y"] + docker_packages,
            check=False,
            capture_output=True,
            text=True,
            env=clean_env,
        )
        if docker_install_result.returncode != 0:
            print_error("Failed to install Docker Engine and Docker Compose plugin.")
            stderr = docker_install_result.stderr or docker_install_result.stdout or ""
            if stderr:
                print_info_verbose(f"Docker install output:\n{stderr}")
            return False

        print_success(
            "[bold]Docker Engine and Docker Compose plugin[/bold] installed successfully.",
            items=[f"[dim]{pkg}[/dim]" for pkg in docker_packages],
            panel=True,
        )

        docker_installed, docker_version = is_official_docker_installed()
        compose_available, compose_version = is_docker_compose_plugin_available()
        if docker_installed and compose_available:
            print_success(
                "[bold]Docker installation verification[/bold] successful",
                items=[
                    f"[cyan]Docker:[/cyan] {docker_version}",
                    f"[cyan]Docker Compose:[/cyan] {compose_version}",
                ],
                panel=True,
            )
            return True

        print_warning(
            "Docker or Docker Compose plugin verification failed after installation."
        )
        return False
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("An unexpected error occurred during Docker installation.")
        print_exception(show_locals=False, exception=exc)
        return False


__all__ = [
    "install_docker_prerequisites",
]
