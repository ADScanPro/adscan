"""Update management for the ADscan launcher and Docker image.

This module lives in `adscan_launcher` because updates are a host-side concern:
- Update the launcher package (pipx/pip).
- Update the Docker image used to run the in-container ADscan runtime.

The full repository provides richer dependency injection from `adscan.py`, but
the PyPI launcher uses the same logic with a smaller set of injected helpers.
"""

# pylint: disable=too-many-instance-attributes,broad-exception-caught

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Callable

from packaging import version
import requests
from rich.console import Group
from rich.text import Text


@dataclass(frozen=True)
class UpdateContext:
    """Dependency injection container for update operations."""

    adscan_base_dir: str
    docker_pull_timeout_seconds: int | None
    get_installed_version: Callable[[], str]
    detect_installer: Callable[[], str]
    get_clean_env_for_compilation: Callable[[], dict[str, str]]
    run_pip_install_with_optional_break_system_packages: Callable[..., None]
    mark_passthrough: Callable[[str], str]
    telemetry_capture_exception: Callable[[Exception], None]
    get_docker_image_name: Callable[[], str]
    image_exists: Callable[[str], bool]
    ensure_image_pulled: Callable[..., bool]
    run_docker: Callable[..., subprocess.CompletedProcess[str]]
    is_container_runtime: Callable[[], bool]
    sys_stdin_isatty: Callable[[], bool]
    os_getenv: Callable[[str, str | None], str | None]
    print_info: Callable[[str], None]
    print_info_debug: Callable[[str], None]
    print_warning: Callable[[str], None]
    print_instruction: Callable[[str], None]
    print_error: Callable[[str], None]
    print_success: Callable[[str], None]
    print_panel: Callable[..., None]
    confirm_ask: Callable[[str, bool], bool]


def get_launcher_update_info(ctx: UpdateContext) -> dict:
    """Return current/latest launcher versions and whether an update is available."""
    info: dict[str, object] = {
        "current": ctx.get_installed_version(),
        "latest": None,
        "is_newer": False,
        "error": None,
    }
    try:
        raw_check_url = "https://pypi.org/pypi/adscan/json"
        check_url = ctx.mark_passthrough(raw_check_url)
        ctx.print_info("Checking for newer ADscan version...")
        ctx.print_info_debug(
            f"[version-check] Using URL: {check_url} | current version: {info['current']}"
        )
        resp = requests.get(check_url, timeout=5)
        latest = resp.json().get("info", {}).get("version")
        info["latest"] = latest
        ctx.print_info_debug(
            f"[version-check] Response: status={getattr(resp, 'status_code', None)} "
            f"| current={info['current']} | latest={latest}"
        )
        if not latest or latest == info["current"]:
            return info
        try:
            info["is_newer"] = version.parse(str(latest)) > version.parse(
                str(info["current"])
            )
        except Exception:
            ctx.print_info_debug(
                "[version-check] Failed to compare versions via packaging; falling back "
                "to string comparison"
            )
            info["is_newer"] = str(latest) > str(info["current"])
        return info
    except Exception as exc:
        ctx.telemetry_capture_exception(exc)
        info["error"] = str(exc)
        return info


def _get_local_image_digest(ctx: UpdateContext, image: str) -> dict:
    """Return local image digest/id for a Docker image (best-effort)."""
    info: dict[str, object] = {"digest": None, "image_id": None}
    try:
        proc = ctx.run_docker(
            ["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"],
            check=False,
            capture_output=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            digests = json.loads(proc.stdout.strip())
            if isinstance(digests, list) and digests:
                first = digests[0]
                if isinstance(first, str) and "@" in first:
                    info["digest"] = first.split("@", 1)[1]
        elif proc.stderr:
            info["error"] = proc.stderr.strip()
        proc = ctx.run_docker(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
            check=False,
            capture_output=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            info["image_id"] = proc.stdout.strip()
        elif proc.stderr and not info.get("error"):
            info["error"] = proc.stderr.strip()
    except Exception as exc:
        info["error"] = str(exc)
    return info


def _get_remote_image_digest(ctx: UpdateContext, image: str) -> dict:
    """Return remote image digest from docker manifest inspect (best-effort)."""
    info: dict[str, object] = {"digest": None, "error": None}
    try:
        proc = ctx.run_docker(
            ["docker", "manifest", "inspect", image],
            check=False,
            capture_output=True,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            info["error"] = proc.stderr.strip() or "manifest inspect failed"
            return info
        payload = json.loads(proc.stdout)
        if isinstance(payload, dict):
            config = payload.get("config") or {}
            digest = config.get("digest")
            if digest:
                info["digest"] = digest
                return info
            manifests = payload.get("manifests") or []
            if manifests:
                info["digest"] = manifests[0].get("digest")
        return info
    except Exception as exc:
        info["error"] = str(exc)
        return info


def get_docker_update_info(ctx: UpdateContext) -> dict:
    """Return update status for the Docker image (best-effort)."""
    info: dict[str, object] = {
        "image": ctx.get_docker_image_name(),
        "local_digest": None,
        "local_image_id": None,
        "remote_digest": None,
        "needs_update": False,
        "error": None,
        "image_present": False,
        "remote_checked": False,
    }
    if ctx.is_container_runtime():
        info["error"] = "container-runtime"
        ctx.print_info_debug("[update] Skipping Docker update check inside container.")
        return info
    if shutil.which("docker") is None:
        info["error"] = "docker-not-found"
        ctx.print_info_debug("[update] Docker not found; skipping image update check.")
        return info
    try:
        image = str(info["image"])
        if not ctx.image_exists(image):
            info["needs_update"] = True
            ctx.print_info_debug(f"[update] Docker image missing locally: {image}")
            return info
        info["image_present"] = True
        local = _get_local_image_digest(ctx, image)
        info["local_digest"] = local.get("digest")
        info["local_image_id"] = local.get("image_id")
        if local.get("error"):
            ctx.print_info_debug(f"[update] Local inspect error: {local['error']}")
        ctx.print_info_debug(
            "[update] Local image info: "
            f"digest={info['local_digest']}, id={info['local_image_id']}"
        )
        remote = _get_remote_image_digest(ctx, image)
        info["remote_checked"] = bool(
            remote.get("digest") is not None or remote.get("error") is not None
        )
        info["remote_digest"] = remote.get("digest")
        if remote.get("error"):
            ctx.print_info_debug(
                f"[update] Remote manifest inspect failed: {remote['error']}"
            )
        if info["remote_digest"]:
            ctx.print_info_debug(
                f"[update] Remote image digest: {info['remote_digest']}"
            )

        # Docker may expose two different digest kinds:
        # - local RepoDigest: manifest digest (from .RepoDigests)
        # - local image Id: config/content digest (from .Id)
        # `docker manifest inspect` commonly returns config digest first.
        if info["remote_digest"]:
            compare_target = info["local_image_id"] or info["local_digest"]
            if compare_target:
                info["needs_update"] = info["remote_digest"] != compare_target
                ctx.print_info_debug(
                    "[update] Digest comparison: "
                    f"remote={info['remote_digest']} vs local={compare_target} "
                    f"=> needs_update={info['needs_update']}"
                )
        return info
    except Exception as exc:
        ctx.telemetry_capture_exception(exc)
        info["error"] = str(exc)
        return info


def _update_launcher(ctx: UpdateContext, latest_version: str | None = None) -> bool:
    """Update the launcher (pipx/pip). Returns True if an update was attempted."""
    installer = ctx.detect_installer()
    if installer == "pipx":
        try:
            proc = subprocess.run(["pipx", "upgrade", "adscan"], check=False)
            if proc.returncode != 0:
                ctx.print_error("Failed to update the launcher via pipx.")
                ctx.print_instruction("Try: pipx upgrade adscan")
                return False
            return True
        except Exception as exc:
            ctx.telemetry_capture_exception(exc)
            ctx.print_error("Failed to update the launcher via pipx.")
            ctx.print_instruction("Try: pipx upgrade adscan")
            return False
    pip_python = shutil.which("python3") or shutil.which("python")
    if not pip_python:
        ctx.print_error("python3 not found; cannot update via pip.")
        return False
    try:
        clean_env = ctx.get_clean_env_for_compilation()
        ctx.run_pip_install_with_optional_break_system_packages(
            python_executable=pip_python,
            args=["--upgrade", "adscan"],
            env=clean_env,
            prefer_break_system_packages=True,
        )
    except Exception as exc:
        ctx.telemetry_capture_exception(exc)
        ctx.print_error("Failed to update the launcher via pip.")
        ctx.print_instruction("Try: python3 -m pip install --upgrade adscan")
        ctx.print_info_debug(f"[update] pip upgrade error: {exc}")
        return False
    if latest_version:
        try:
            ver_dir = Path(ctx.adscan_base_dir)
            ver_dir.mkdir(parents=True, exist_ok=True)
            (ver_dir / "version").write_text(latest_version, encoding="utf-8")
        except Exception:
            pass
    return True


def _update_docker_image(ctx: UpdateContext, image: str) -> bool:
    """Pull the Docker image to latest. Returns True if pull succeeded."""
    ctx.print_info(f"Pulling image: {image}")
    pull_start = time.monotonic()
    pull_timeout = ctx.docker_pull_timeout_seconds
    ok = ctx.ensure_image_pulled(image, timeout=pull_timeout, stream_output=True)
    ctx.print_info_debug(
        f"[update] Docker pull duration: {time.monotonic() - pull_start:.2f}s"
    )
    if not ok:
        ctx.print_error("Failed to pull the ADscan Docker image.")
        ctx.print_instruction(f"Try: docker pull {image}")
        return False
    ctx.print_success("ADscan Docker image pulled successfully.")
    return True


def _render_update_panel(
    ctx: UpdateContext, launcher_info: dict, docker_info: dict
) -> None:
    """Render a concise update summary panel."""
    lines: list[Text] = []
    current = launcher_info.get("current") or "unknown"
    latest = launcher_info.get("latest") or "unknown"
    if launcher_info.get("is_newer"):
        lines.append(
            Text(
                f"Launcher update available: {current} → {latest}", style="bold yellow"
            )
        )
    else:
        lines.append(Text(f"Launcher: {current} (up-to-date)", style="green"))

    image = docker_info.get("image") or "unknown"
    if docker_info.get("needs_update"):
        lines.append(
            Text(f"Docker image update available: {image}", style="bold yellow")
        )
    elif docker_info.get("image_present"):
        lines.append(Text(f"Docker image: {image} (up-to-date)", style="green"))
    else:
        lines.append(Text(f"Docker image missing: {image}", style="yellow"))

    ctx.print_panel(
        Group(*lines),
        title="Updates",
        border_style=None,
        padding=(1, 2),
    )


def offer_updates_for_command(ctx: UpdateContext, command: str) -> None:
    """Check for launcher/docker updates and offer upgrades (interactive only)."""
    if ctx.is_container_runtime():
        return
    if command in {"update", "upgrade"}:
        return
    if command not in {"start", "ci", "check"}:
        return

    # Maintainer dev channel should not show update checks/prompts.
    docker_channel = str(ctx.os_getenv("ADSCAN_DOCKER_CHANNEL", "") or "").strip().lower()
    docker_image = str(ctx.get_docker_image_name() or "").strip().lower()
    image_no_digest = docker_image.split("@", 1)[0]
    image_repo = image_no_digest.split(":", 1)[0]
    image_tag = image_no_digest.split(":", 1)[1] if ":" in image_no_digest else ""
    is_dev_image = image_repo.endswith("-dev") or image_tag == "edge"
    if docker_channel == "dev" or is_dev_image:
        ctx.print_info_debug(
            "[update] Dev channel detected; skipping launcher/docker update checks."
        )
        return

    # `adscan ci` is explicitly non-interactive and must never block on prompts,
    # even when executed in a real TTY and without CI env markers.
    if command == "ci" or (ctx.os_getenv("ADSCAN_SESSION_ENV", None) == "ci"):
        ctx.print_info("CI mode detected; skipping update prompts.")
        ctx.print_instruction("Run: adscan update")
        return

    launcher_info = get_launcher_update_info(ctx)
    docker_info = get_docker_update_info(ctx)
    if not launcher_info.get("is_newer") and not docker_info.get("needs_update"):
        return

    _render_update_panel(ctx, launcher_info, docker_info)

    if (
        ctx.os_getenv("CI", None)
        or ctx.os_getenv("GITHUB_ACTIONS", None)
        or ctx.os_getenv("CONTINUOUS_INTEGRATION", None)
        or not ctx.sys_stdin_isatty()
    ):
        ctx.print_info("Non-interactive environment detected; skipping update prompts.")
        ctx.print_instruction("Run: adscan update")
        return

    if launcher_info.get("is_newer"):
        if ctx.confirm_ask("Update the launcher now?", True):
            if _update_launcher(ctx, str(launcher_info.get("latest") or "")):
                ctx.print_success("Launcher update completed, restarting...")
                os.execv(sys.executable, [sys.executable] + sys.argv)

    if docker_info.get("needs_update"):
        if ctx.confirm_ask("Update the Docker image now?", False):
            _update_docker_image(
                ctx, str(docker_info.get("image") or ctx.get_docker_image_name())
            )


def run_update_command(ctx: UpdateContext) -> bool:
    """Update both launcher and Docker image.

    Returns:
        True when the update completed without fatal errors; False otherwise.
    """
    if ctx.is_container_runtime():
        ctx.print_warning("Update must be run on the host, not inside the container.")
        return False
    launcher_info = get_launcher_update_info(ctx)
    docker_info = get_docker_update_info(ctx)
    _render_update_panel(ctx, launcher_info, docker_info)

    ok = True
    updated_launcher = False
    if launcher_info.get("is_newer"):
        updated_launcher = _update_launcher(ctx, str(launcher_info.get("latest") or ""))
        ok = ok and bool(updated_launcher)
    else:
        ctx.print_info("Launcher already up-to-date.")

    image_name = str(docker_info.get("image") or ctx.get_docker_image_name())
    if docker_info.get("needs_update") or not docker_info.get("image_present"):
        ok = _update_docker_image(ctx, image_name) and ok
    else:
        ctx.print_info("Docker image already up-to-date.")

    if updated_launcher:
        ctx.print_success("Updates completed, restarting...")
        os.execv(sys.executable, [sys.executable] + sys.argv)
    return ok


def handle_update_command(ctx: UpdateContext) -> None:
    """Update both launcher and Docker image (legacy signature)."""
    run_update_command(ctx)
