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
from datetime import datetime, timezone
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

from adscan_launcher.docker_commands import pull_runtime_image_with_diagnostics


_UPDATE_HEALTH_FILENAME = "update_health.json"
_STALE_UPDATE_WARNING_DAYS = 14


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


def is_dev_update_context(
    *,
    os_getenv: Callable[[str, str | None], str | None] = os.getenv,
    image_name: str | None = None,
) -> bool:
    """Return whether update/version UX should be suppressed for dev workflows."""
    docker_channel = str(os_getenv("ADSCAN_DOCKER_CHANNEL", "") or "").strip().lower()
    session_env = str(os_getenv("ADSCAN_SESSION_ENV", "") or "").strip().lower()
    runtime_image = str(os_getenv("ADSCAN_RUNTIME_IMAGE", "") or "").strip().lower()
    candidate_image = str(image_name or runtime_image or "").strip().lower()
    image_no_digest = candidate_image.split("@", 1)[0]
    image_repo = image_no_digest.split(":", 1)[0]
    image_tag = image_no_digest.split(":", 1)[1] if ":" in image_no_digest else ""
    return (
        docker_channel == "dev"
        or session_env == "dev"
        or image_repo.endswith("-dev")
        or image_tag == "edge"
    )


def _get_update_health_path(adscan_base_dir: str) -> Path:
    """Return the JSON file used for local update health metadata."""
    return Path(adscan_base_dir) / _UPDATE_HEALTH_FILENAME


def read_local_update_health(adscan_base_dir: str) -> dict[str, object]:
    """Return persisted local update health metadata when available."""
    path = _get_update_health_path(adscan_base_dir)
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def get_local_update_recency_summary(
    adscan_base_dir: str,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """Return local update recency metadata derived from persisted state."""
    payload = read_local_update_health(adscan_base_dir)
    last_success_raw = str(payload.get("last_success_at") or "").strip()
    if not last_success_raw:
        return {
            "has_successful_update": False,
            "is_stale": True,
            "age_days": None,
            "message": "No successful local update recorded yet.",
        }
    try:
        last_success_at = datetime.fromisoformat(last_success_raw)
    except ValueError:
        return {
            "has_successful_update": False,
            "is_stale": True,
            "age_days": None,
            "message": "Last successful local update timestamp is unreadable.",
        }
    if last_success_at.tzinfo is None:
        last_success_at = last_success_at.replace(tzinfo=timezone.utc)
    current_time = now or datetime.now(timezone.utc)
    age_days = max(0, int((current_time - last_success_at).total_seconds() // 86400))
    is_stale = age_days >= _STALE_UPDATE_WARNING_DAYS
    return {
        "has_successful_update": True,
        "is_stale": is_stale,
        "age_days": age_days,
        "message": (
            f"Last successful local update: {last_success_raw}"
            if not is_stale
            else f"Last successful local update: {last_success_raw} ({age_days}d old)"
        ),
    }


def _write_local_update_health(adscan_base_dir: str, payload: dict[str, object]) -> None:
    """Persist local update health metadata best-effort."""
    path = _get_update_health_path(adscan_base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _record_update_health(
    ctx: UpdateContext,
    *,
    ok: bool,
    updated_launcher: bool,
    updated_runtime: bool,
) -> None:
    """Persist local metadata about the last update attempt and success."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = read_local_update_health(ctx.adscan_base_dir)
    payload["last_attempt_at"] = now.isoformat()
    payload["last_attempt_ok"] = ok
    payload["last_attempt_launcher_updated"] = updated_launcher
    payload["last_attempt_runtime_updated"] = updated_runtime
    payload["installer"] = ctx.detect_installer()
    payload["docker_image"] = ctx.get_docker_image_name()
    try:
        payload["launcher_version"] = str(ctx.get_installed_version() or "").strip()
    except Exception as exc:  # pragma: no cover - defensive guard
        ctx.telemetry_capture_exception(exc)
    if ok:
        payload["last_success_at"] = now.isoformat()
        payload["last_success_launcher_updated"] = updated_launcher
        payload["last_success_runtime_updated"] = updated_runtime
    try:
        _write_local_update_health(ctx.adscan_base_dir, payload)
    except Exception as exc:  # pragma: no cover - best effort persistence
        ctx.telemetry_capture_exception(exc)
        ctx.print_info_debug(f"[update] Failed to persist local update health: {exc}")


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
    return True


def _launcher_version_matches(ctx: UpdateContext, expected_version: str | None) -> bool:
    """Return whether the installed launcher version matches the expected target."""
    if not expected_version:
        return False
    try:
        installed_version = str(ctx.get_installed_version() or "").strip()
    except Exception as exc:  # pragma: no cover - defensive guard
        ctx.telemetry_capture_exception(exc)
        ctx.print_info_debug(f"[update] Failed to re-read installed version: {exc}")
        return False
    if installed_version == str(expected_version).strip():
        return True
    ctx.print_warning(
        "Launcher update command finished, but the installed launcher version did not change."
    )
    ctx.print_info_debug(
        "[update] Launcher version mismatch after update attempt: "
        f"expected={expected_version}, installed={installed_version}"
    )
    ctx.print_instruction("Rerun `adscan update` from the host after fixing launcher install permissions/state.")
    return False


def _update_docker_image(
    ctx: UpdateContext,
    image: str,
    *,
    command_name: str,
) -> bool:
    """Pull the Docker image to latest. Returns True if pull succeeded."""
    ctx.print_info(f"Pulling image: {image}")
    pull_start = time.monotonic()
    resolved_image = pull_runtime_image_with_diagnostics(
        image=image,
        pull_timeout_seconds=ctx.docker_pull_timeout_seconds,
        command_name=command_name,
        stream_output=True,
    )
    ctx.print_info_debug(
        f"[update] Docker pull duration: {time.monotonic() - pull_start:.2f}s"
    )
    if not resolved_image:
        return False
    ctx.print_success("ADscan Docker image pulled successfully.")
    return True


def _render_update_panel(
    ctx: UpdateContext, launcher_info: dict, docker_info: dict
) -> None:
    """Render an update summary panel with clear operational guidance."""
    lines: list[Text] = []
    current = launcher_info.get("current") or "unknown"
    latest = launcher_info.get("latest") or "unknown"
    update_needed = bool(
        launcher_info.get("is_newer") or docker_info.get("needs_update")
    )
    if launcher_info.get("is_newer"):
        lines.append(
            Text(
                f"Launcher update available: {current} → {latest}", style="bold yellow"
            )
        )
    else:
        lines.append(Text(f"Launcher: {current} (up-to-date)", style="green"))

    image = docker_info.get("image") or "unknown"
    if not docker_info.get("image_present"):
        lines.append(Text(f"Docker image missing locally: {image}", style="yellow"))
    elif docker_info.get("needs_update"):
        lines.append(
            Text(f"Docker image update available: {image}", style="bold yellow")
        )
    elif docker_info.get("image_present"):
        lines.append(Text(f"Docker image: {image} (up-to-date)", style="green"))

    if update_needed:
        if launcher_info.get("is_newer") and docker_info.get("needs_update"):
            action_text = (
                "Action: refresh both the launcher and runtime image together."
            )
        elif launcher_info.get("is_newer"):
            action_text = "Action: refresh the launcher from the host."
        else:
            action_text = "Action: refresh the runtime image from the host."
        lines.append(
            Text(
                "Recommended: keep both launcher and runtime updated for bug fixes, "
                "new attack coverage, and escalation improvements.",
                style="cyan",
            )
        )
        lines.append(
            Text(
                action_text,
                style="white",
            )
        )
        lines.append(
            Text(
                "Run on the host: adscan update",
                style="bold white",
            )
        )
    recency = get_local_update_recency_summary(ctx.adscan_base_dir)
    recency_message = str(recency.get("message") or "").strip()
    if recency_message:
        lines.append(
            Text(
                recency_message,
                style="yellow" if bool(recency.get("is_stale")) else "dim",
            )
        )
    if bool(recency.get("is_stale")):
        lines.append(
            Text(
                f"Recommendation: update at least every {_STALE_UPDATE_WARNING_DAYS} days.",
                style="bold yellow",
            )
        )

    ctx.print_panel(
        Group(*lines),
        title="Updates Required" if update_needed else "Updates",
        border_style="yellow" if update_needed else None,
        padding=(1, 2),
    )


def _confirm_skip_update(ctx: UpdateContext, *, component_label: str) -> bool:
    """Ask the operator to confirm skipping a recommended update."""
    ctx.print_warning(
        f"Skipping the {component_label} update is not recommended. "
        "The latest release is typically the most stable and includes the newest fixes and features."
    )
    return ctx.confirm_ask(
        f"Are you sure you want to continue without updating the {component_label}?",
        False,
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
    docker_image = str(ctx.get_docker_image_name() or "").strip().lower()
    if is_dev_update_context(os_getenv=ctx.os_getenv, image_name=docker_image):
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
        recency = get_local_update_recency_summary(ctx.adscan_base_dir)
        if bool(recency.get("is_stale")):
            ctx.print_warning(str(recency.get("message") or "Local update cadence looks stale."))
        ctx.print_info(
            "Running with a stale launcher or runtime image can produce incorrect checks, "
            "missed fixes, and older attack coverage."
        )
        ctx.print_instruction("Run: adscan update")
        return

    if launcher_info.get("is_newer"):
        if ctx.confirm_ask("Update the launcher now?", True):
            if _update_launcher(ctx, str(launcher_info.get("latest") or "")):
                ctx.print_success("Launcher update completed, restarting...")
                os.execv(sys.executable, [sys.executable] + sys.argv)
        elif not _confirm_skip_update(ctx, component_label="launcher"):
            if _update_launcher(ctx, str(launcher_info.get("latest") or "")):
                ctx.print_success("Launcher update completed, restarting...")
                os.execv(sys.executable, [sys.executable] + sys.argv)

    if docker_info.get("needs_update"):
        image_missing_locally = not bool(docker_info.get("image_present"))
        docker_prompt = (
            "Docker image is required locally for runtime commands. Pull now?"
            if image_missing_locally
            else "Update the Docker image now?"
        )
        if ctx.confirm_ask(docker_prompt, image_missing_locally):
            update_ok = _update_docker_image(
                ctx,
                str(docker_info.get("image") or ctx.get_docker_image_name()),
                command_name=command,
            )
            if image_missing_locally and not update_ok:
                ctx.print_error(
                    "ADscan runtime image is still unavailable, so the command cannot continue."
                )
                ctx.print_instruction(
                    "Resolve Docker/image pull issues first, then retry the same command."
                )
                raise SystemExit(1)
        elif not _confirm_skip_update(ctx, component_label="runtime image"):
            _update_docker_image(
                ctx,
                str(docker_info.get("image") or ctx.get_docker_image_name()),
                command_name=command,
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
    launcher_restart_ready = False
    docker_updated = False
    if launcher_info.get("is_newer"):
        updated_launcher = _update_launcher(ctx, str(launcher_info.get("latest") or ""))
        ok = ok and bool(updated_launcher)
        if updated_launcher:
            launcher_restart_ready = _launcher_version_matches(
                ctx, str(launcher_info.get("latest") or "")
            )
            ok = ok and launcher_restart_ready
    else:
        ctx.print_info("Launcher already up-to-date.")

    image_name = str(docker_info.get("image") or ctx.get_docker_image_name())
    if docker_info.get("needs_update") or not docker_info.get("image_present"):
        docker_updated = _update_docker_image(ctx, image_name, command_name="update")
        ok = docker_updated and ok
    else:
        ctx.print_info("Docker image already up-to-date.")

    _record_update_health(
        ctx,
        ok=ok,
        updated_launcher=updated_launcher,
        updated_runtime=docker_updated,
    )

    if updated_launcher and launcher_restart_ready:
        ctx.print_success("Updates completed, restarting...")
        os.execv(sys.executable, [sys.executable] + sys.argv)
    return ok


def handle_update_command(ctx: UpdateContext) -> None:
    """Update both launcher and Docker image (legacy signature)."""
    run_update_command(ctx)
