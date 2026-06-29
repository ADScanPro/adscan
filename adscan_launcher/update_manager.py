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


# ---------------------------------------------------------------------------
# Update severity tiers + release-highlights catalogue
# ---------------------------------------------------------------------------
#
# Why three tiers exist (TUI-design Principle 6, "semantic color encodes
# meaning"): a generic "Recommended" prompt does not move the user who
# does not see the value. Telemetry from 2026-05-21 confirmed the
# pattern — a v8.0.0 user declined the launcher update, pulled the
# v9.0.0 image anyway, and ended up in a mismatched state. The fix is
# to escalate visual urgency *and* surface concrete value when the
# version delta crosses a major boundary.
#
# Severity rules (computed by ``compute_update_severity``):
#
#   ``tier_info``     — same major, newer minor/patch available
#   ``tier_warn``     — exactly 1 major behind
#   ``tier_critical`` — 2+ majors behind, OR launcher/image major
#                       mismatch detected (the "broken combination"
#                       case that surfaces as inexplicable bug reports
#                       from users in an unsupported launcher+image
#                       combination)

_TIER_INFO = "info"
_TIER_WARN = "warn"
_TIER_CRITICAL = "critical"


# Panel copy strategy — read this before touching the strings below.
#
# We deliberately do NOT link to per-version release notes here. Two
# reasons: (1) maintaining per-release prose is human-expensive and the
# release docs are often sparse for minor/patch bumps, (2) pointing at a
# thin changelog page actively hurts conversion — the operator clicks,
# sees "minor improvements", and decides not to update.
#
# Instead we use loss-aversion framing: every release fixes bugs and
# adds coverage; running stale means hitting bugs already fixed and
# missing techniques already shipped. That copy is true for every
# version transition the product will ever see, so it never goes
# stale, and it answers the question the operator actually asks at
# the prompt ("what do I lose by skipping?") rather than the one we
# can't reliably answer ("what's specifically new in v9.1.0?").


def _parse_major(value_str: str) -> int | None:
    """Best-effort major-version parser. Returns ``None`` if unparsable."""
    if not value_str:
        return None
    try:
        return version.parse(str(value_str)).major  # type: ignore[union-attr]
    except Exception:
        return None


def _build_version_delta_summary(
    *,
    current: str,
    latest: str | None,
    majors_behind: int | None,
) -> tuple[str, str]:
    """Return ``(delta_line, motivation_line)`` for the update panel.

    ``delta_line`` states the objective version gap ("8.0.0 → 9.0.0",
    "2 majors behind"). It is factual and short.

    ``motivation_line`` is loss-aversion framing tuned to the tier.
    Each line is version-agnostic and stays true for any release
    delta the product will ever see — so the launcher never needs
    per-release prose to keep its CTA compelling.

    Both lines are empty strings when no update is available.
    """
    if not latest or not current or current == latest:
        return ("", "")

    if majors_behind is not None and majors_behind >= 2:
        delta = (
            f"You are {majors_behind} major versions behind "
            f"(running {current}, latest is {latest})."
        )
        motivation = (
            "Each major release ships material improvements: new attack "
            "coverage, fixes to core AD flows, and posture handling for "
            "modern Active Directory configurations. Running this many "
            "majors behind means hitting bugs that have been fixed for a "
            "long time and missing techniques that already exist."
        )
        return (delta, motivation)

    if majors_behind is not None and majors_behind == 1:
        delta = f"A new major version is available ({current} → {latest})."
        motivation = (
            "Major releases of ADscan ship material improvements — "
            "expanded attack coverage, refactored core flows, fixes that "
            "do not get backported. Staying on the previous major means "
            "hitting bugs that are already resolved upstream and missing "
            "techniques that already shipped."
        )
        return (delta, motivation)

    # Minor / patch bump: keep it short and motivating.
    delta = f"Update available: {current} → {latest}."
    motivation = (
        "Every release of ADscan fixes real bugs and ships small "
        "improvements. Staying on a stale version means hitting issues "
        "that other operators have already had fixed for them."
    )
    return (delta, motivation)


def get_image_baked_version(ctx: "UpdateContext", image: str) -> str | None:
    """Read the ADscan version baked into the runtime image.

    Inspects the image's ``Config.Labels`` for the OCI standard
    ``org.opencontainers.image.version`` label. Returns ``None`` if the
    label is absent or Docker is not reachable.

    The label is written at build time by ``Dockerfile.runtime`` so the
    runtime container can be asked "what version are you?" without
    running it. Parsing the tag is unreliable (people pin ``latest``,
    ``edge``, custom partner tags) — the label is the authoritative
    source.
    """
    if shutil.which("docker") is None:
        return None
    try:
        proc = ctx.run_docker(
            [
                "docker",
                "image",
                "inspect",
                image,
                "--format",
                '{{ index .Config.Labels "org.opencontainers.image.version" }}',
            ],
            check=False,
            capture_output=True,
        )
        if proc.returncode != 0:
            return None
        baked = str(proc.stdout or "").strip()
        return baked or None
    except Exception as exc:  # noqa: BLE001
        ctx.telemetry_capture_exception(exc)
        return None


def compute_update_severity(
    *,
    launcher_current: str,
    launcher_latest: str | None,
    image_present: bool,
    image_needs_update: bool,
    image_baked_version: str | None,
) -> dict[str, object]:
    """Classify the update situation into a severity tier.

    Returns a dict with keys:
        ``tier``: one of ``info`` / ``warn`` / ``critical`` / ``none``.
        ``mismatch``: True iff launcher and image are on different
            majors (the unsupported combination).
        ``majors_behind``: how many majors the launcher is behind the
            latest PyPI release. ``None`` if unknown.
        ``highlights``: list of strings to surface in the panel for
            value framing. Empty for ``tier_info``.

    The tier governs panel chrome (color, glyph, copy density) and the
    update flow (countdown duration, whether skip is allowed).
    """
    current_major = _parse_major(launcher_current)
    latest_major = _parse_major(launcher_latest) if launcher_latest else None
    image_major = _parse_major(image_baked_version)

    mismatch = (
        current_major is not None
        and image_major is not None
        and current_major != image_major
    )

    majors_behind: int | None = None
    if current_major is not None and latest_major is not None:
        majors_behind = max(0, latest_major - current_major)

    needs_attention = (
        (launcher_latest is not None and launcher_latest != launcher_current)
        or image_needs_update
        or not image_present
        or mismatch
    )
    if not needs_attention:
        return {
            "tier": "none",
            "mismatch": False,
            "majors_behind": majors_behind,
            "delta": "",
            "motivation": "",
        }

    if mismatch or (majors_behind is not None and majors_behind >= 2):
        tier = _TIER_CRITICAL
    elif majors_behind is not None and majors_behind >= 1:
        tier = _TIER_WARN
    else:
        tier = _TIER_INFO

    delta, motivation = _build_version_delta_summary(
        current=launcher_current,
        latest=launcher_latest,
        majors_behind=majors_behind,
    )

    return {
        "tier": tier,
        "mismatch": mismatch,
        "majors_behind": majors_behind,
        "delta": delta,
        "motivation": motivation,
    }


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
    current_time = now or datetime.now(timezone.utc)
    last_success_raw = str(payload.get("last_success_at") or "").strip()
    last_attempt_raw = str(payload.get("last_attempt_at") or "").strip()
    last_attempt_ok = payload.get("last_attempt_ok")
    if not last_success_raw:
        if last_attempt_raw and last_attempt_ok is False:
            return {
                "status": "failed_attempt",
                "has_successful_update": False,
                "is_stale": True,
                "age_days": None,
                "install_initialized_at": str(payload.get("install_initialized_at") or "").strip() or None,
                "message": f"Previous local update attempt failed: {last_attempt_raw}",
            }
        install_initialized_at = str(payload.get("install_initialized_at") or "").strip()
        if not install_initialized_at:
            install_initialized_at = current_time.replace(microsecond=0).isoformat()
            payload["install_initialized_at"] = install_initialized_at
            try:
                _write_local_update_health(adscan_base_dir, payload)
            except OSError:
                pass
        return {
            "status": "bootstrap",
            "has_successful_update": False,
            "is_stale": False,
            "age_days": None,
            "install_initialized_at": install_initialized_at or None,
            "message": (
                "No successful local update recorded yet. "
                "This is normal on a first install until `adscan update` runs."
            ),
        }
    try:
        last_success_at = datetime.fromisoformat(last_success_raw)
    except ValueError:
        return {
            "status": "invalid_success_timestamp",
            "has_successful_update": False,
            "is_stale": True,
            "age_days": None,
            "install_initialized_at": str(payload.get("install_initialized_at") or "").strip() or None,
            "message": "Last successful local update timestamp is unreadable.",
        }
    if last_success_at.tzinfo is None:
        last_success_at = last_success_at.replace(tzinfo=timezone.utc)
    age_days = max(0, int((current_time - last_success_at).total_seconds() // 86400))
    is_stale = age_days >= _STALE_UPDATE_WARNING_DAYS
    return {
        "status": "stale" if is_stale else "fresh",
        "has_successful_update": True,
        "is_stale": is_stale,
        "age_days": age_days,
        "install_initialized_at": str(payload.get("install_initialized_at") or "").strip() or None,
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


def _extract_index_digest_from_buildx(stdout: str) -> str | None:
    """Parse the index digest from ``buildx imagetools inspect --format {{json .Manifest}}``.

    The ``.Manifest`` object is the top-level descriptor the registry serves for
    the tag. Its ``.digest`` is the index/manifest digest — the SAME hash kind a
    locally pulled image records in ``.RepoDigests`` (``name@sha256:<index>``).
    This is the only value that is type-consistent with the local RepoDigest for
    the multi-arch manifest-list images ADscan publishes.
    """
    payload = json.loads(stdout)
    if isinstance(payload, dict):
        digest = payload.get("digest")
        if isinstance(digest, str) and digest:
            return digest
    return None


def _extract_index_digest_from_verbose(stdout: str) -> str | None:
    """Parse the index digest from ``docker manifest inspect --verbose``.

    The ``--verbose`` output wraps the contents in a top-level ``Descriptor``
    whose ``digest`` is the index/manifest digest (matches the local
    RepoDigest). The non-verbose form does NOT expose this — it emits the
    CONTENTS (a ``config`` digest for a single manifest, or per-platform child
    ``manifests[]`` digests for a manifest list), neither of which is comparable
    to the local RepoDigest. So the fallback must use ``--verbose``.
    """
    payload = json.loads(stdout)
    # `--verbose` on a single-arch tag returns one object; on a manifest list it
    # returns a JSON array of per-platform objects. Every entry carries the SAME
    # index digest in its `Descriptor`, so the first match wins.
    if isinstance(payload, list):
        payload = payload[0] if payload else {}
    if isinstance(payload, dict):
        descriptor = payload.get("Descriptor") or {}
        digest = descriptor.get("digest")
        if isinstance(digest, str) and digest:
            return digest
    return None


def _get_remote_image_digest(ctx: UpdateContext, image: str) -> dict:
    """Return the remote INDEX digest for a tag (best-effort).

    The comparison that determines ``needs_update`` must be type-consistent:
    local ``.RepoDigests`` holds the index/manifest digest
    (``name@sha256:<index>``), so the remote side must yield the SAME hash kind.
    Plain ``docker manifest inspect`` is structurally incapable of producing it —
    it emits the manifest CONTENTS (``config.digest`` for a single manifest, or
    per-platform child ``manifests[].digest`` for a manifest list), none of which
    equal the local RepoDigest. For multi-arch images (what ADscan publishes)
    that mismatch made ``needs_update`` permanently True and re-prompted on every
    ``adscan start``.

    Resolution order, each best-effort:
      1. ``docker buildx imagetools inspect --format '{{json .Manifest}}'`` →
         ``.digest`` (the index digest). Preferred.
      2. ``docker manifest inspect --verbose`` → ``.Descriptor.digest`` (also the
         index digest). Fallback when buildx is unavailable.

    When neither yields an index digest (buildx missing AND verbose
    unsupported/unreachable), ``digest`` stays ``None`` — the caller must treat
    that as "undeterminable" and NOT flag an update, never default to True.
    """
    info: dict[str, object] = {"digest": None, "error": None}
    # Preferred: buildx imagetools exposes the index digest directly.
    try:
        proc = ctx.run_docker(
            [
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                image,
                "--format",
                "{{json .Manifest}}",
            ],
            check=False,
            capture_output=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            digest = _extract_index_digest_from_buildx(proc.stdout.strip())
            if digest:
                info["digest"] = digest
                return info
        elif proc.stderr:
            info["error"] = proc.stderr.strip()
    except Exception as exc:
        ctx.telemetry_capture_exception(exc)
        info["error"] = str(exc)

    # Fallback: `manifest inspect --verbose` carries the index digest in
    # `.Descriptor.digest`. (The non-verbose form does NOT — never use it here.)
    try:
        proc = ctx.run_docker(
            ["docker", "manifest", "inspect", "--verbose", image],
            check=False,
            capture_output=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            digest = _extract_index_digest_from_verbose(proc.stdout.strip())
            if digest:
                info["digest"] = digest
                info["error"] = None
                return info
            if not info.get("error"):
                info["error"] = "no index digest in manifest inspect --verbose"
        elif proc.stderr and not info.get("error"):
            info["error"] = proc.stderr.strip()
        elif not info.get("error"):
            info["error"] = "manifest inspect --verbose failed"
    except Exception as exc:
        ctx.telemetry_capture_exception(exc)
        if not info.get("error"):
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

        # Type-consistent comparison: BOTH sides must be the index/manifest
        # digest (the `@sha256:` value the image was pulled by).
        #   - local: RepoDigest from `.RepoDigests` (NOT `.Id`, which is the
        #     config-blob digest and a different hash kind).
        #   - remote: index digest from buildx imagetools / manifest inspect
        #     --verbose (see `_get_remote_image_digest`).
        # `.Id` is kept for diagnostics only — comparing it against the remote
        # index digest is what caused the permanent-update loop on multi-arch
        # images.
        local_repo_digest = info["local_digest"]
        remote_index_digest = info["remote_digest"]
        ctx.print_info_debug(
            "[update] Digest comparison inputs: "
            f"local_repo_digest={local_repo_digest} "
            f"local_image_id={info['local_image_id']} "
            f"remote_index_digest={remote_index_digest}"
        )
        if not local_repo_digest:
            # Locally-built image (no RepoDigest) or inspect failure: there is no
            # comparable manifest digest. Do NOT nag — uncertainty must never
            # flag an update.
            ctx.print_info_debug(
                "[update] Local RepoDigest unavailable (locally-built image or "
                "inspect failure); treating as undeterminable, needs_update=False."
            )
        elif not remote_index_digest:
            # Registry unreachable, buildx + verbose both failed, or no index
            # digest exposed. Undeterminable — never flag an update.
            ctx.print_info_debug(
                "[update] Remote index digest unavailable; treating as "
                "undeterminable, needs_update=False."
            )
        else:
            info["needs_update"] = local_repo_digest != remote_index_digest
            ctx.print_info_debug(
                "[update] Digest comparison: "
                f"remote_index={remote_index_digest} vs "
                f"local_repo={local_repo_digest} "
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
    # Target THIS launcher's own interpreter, not whatever python3 is first on
    # PATH. For a venv / `pip install --user` install, `shutil.which("python3")`
    # can resolve to a different (system) interpreter and the upgrade lands in
    # the wrong environment — leaving the running launcher stale.
    pip_python = sys.executable or shutil.which("python3") or shutil.which("python")
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


def _read_installed_version_clean(ctx: UpdateContext) -> str | None:
    """Re-read the on-disk installed `adscan` version in a CLEAN subprocess.

    The in-process ``__version__`` is frozen at import time (computed once via
    ``importlib.metadata.version``), so re-reading it after the upgrade
    subprocess still returns the OLD value — that is exactly what made "update
    twice still stale" self-report a no-op and SKIP the restart. Spawning the
    target env's python re-reads the package metadata fresh from disk, so a
    successful upgrade is actually observed.
    """
    python_exe = sys.executable or shutil.which("python3") or shutil.which("python")
    if not python_exe:
        return None
    try:
        proc = subprocess.run(  # noqa: S603
            [
                python_exe,
                "-c",
                "import importlib.metadata as m; print(m.version('adscan'))",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=ctx.get_clean_env_for_compilation(),
            timeout=30,
        )
    except Exception as exc:  # pragma: no cover - defensive guard
        ctx.telemetry_capture_exception(exc)
        ctx.print_info_debug(f"[update] Clean-subprocess version re-read failed: {exc}")
        return None
    if proc.returncode != 0:
        ctx.print_info_debug(
            "[update] Clean-subprocess version re-read returned "
            f"{proc.returncode}: {(proc.stderr or '').strip()}"
        )
        return None
    return (proc.stdout or "").strip() or None


def _launcher_version_matches(ctx: UpdateContext, expected_version: str | None) -> bool:
    """Return whether the ON-DISK launcher version matches the expected target.

    Uses a clean-subprocess metadata re-read (not the frozen in-process
    ``__version__``) so a successful pip/pipx upgrade is actually detected and
    the post-update restart is not wrongly skipped.
    """
    if not expected_version:
        return False
    installed_version = _read_installed_version_clean(ctx)
    if installed_version is None:
        # We could not verify the on-disk version (no python, timeout, etc.).
        # Do NOT block the restart on an unverifiable read — the upgrade step
        # already returned success, so trust it and let the re-exec fire.
        ctx.print_info_debug(
            "[update] Could not verify on-disk launcher version; trusting "
            "the successful upgrade and proceeding to restart."
        )
        return True
    if installed_version == str(expected_version).strip():
        return True
    ctx.print_warning(
        "Launcher update command finished, but the installed launcher version did not change."
    )
    ctx.print_info_debug(
        "[update] Launcher version mismatch after update attempt: "
        f"expected={expected_version}, installed={installed_version}"
    )
    _print_launcher_restart_hint(ctx)
    return False


def _resolve_launcher_restart_target() -> str | None:
    """Resolve the relocated `adscan` console-script to re-exec.

    ``os.execv(sys.executable, ...)`` re-execs the INTERPRETER, not the
    upgraded console-script, so the freshly installed code may not be picked
    up. Prefer the console-script on PATH (``adscan``); fall back to
    ``sys.argv[0]`` when it points at a real file.
    """
    script = shutil.which("adscan")
    if script:
        return script
    argv0 = sys.argv[0] if sys.argv else ""
    if argv0 and os.path.basename(argv0) in {"adscan", "adscan.exe"}:
        resolved = shutil.which(argv0) or argv0
        if os.path.isfile(resolved):
            return resolved
    return None


def _print_launcher_restart_hint(ctx: UpdateContext) -> None:
    """Tell the operator how to pick up the upgraded launcher when no clean
    in-process re-exec is possible (bash caches the old path until ``hash -r``).
    """
    ctx.print_instruction(
        "Launcher upgraded. Run `hash -r` or open a new terminal, then re-run "
        "`adscan update`."
    )


def _restart_into_upgraded_launcher(ctx: UpdateContext) -> None:
    """Re-exec into the upgraded console-script, or print the shell-hash hint.

    Re-execs the relocated ``adscan`` console-script (not the bare
    interpreter) so the new code is actually loaded. When the script cannot be
    resolved, print the explicit ``hash -r`` / new-terminal instruction rather
    than re-execing the interpreter (which would silently keep running the old
    package).
    """
    target = _resolve_launcher_restart_target()
    if not target:
        _print_launcher_restart_hint(ctx)
        return
    ctx.print_success("Updates completed, restarting...")
    try:
        os.execv(target, [target] + sys.argv[1:])
    except Exception as exc:  # pragma: no cover - defensive guard
        ctx.telemetry_capture_exception(exc)
        ctx.print_info_debug(f"[update] Re-exec into {target!r} failed: {exc}")
        _print_launcher_restart_hint(ctx)


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


_TIER_CHROME: dict[str, dict[str, str]] = {
    _TIER_INFO: {
        "glyph": "ⓘ",
        "border": "cyan",
        "header_style": "bold cyan",
        "title_prefix": "ADscan update available",
    },
    _TIER_WARN: {
        "glyph": "⚠",
        "border": "yellow",
        "header_style": "bold yellow",
        "title_prefix": "MAJOR version behind",
    },
    _TIER_CRITICAL: {
        "glyph": "🚨",
        "border": "red",
        "header_style": "bold red",
        "title_prefix": "VERSION DEPRECATED — update required",
    },
}


def _render_update_panel(
    ctx: UpdateContext,
    launcher_info: dict,
    docker_info: dict,
    *,
    severity: dict[str, object] | None = None,
) -> None:
    """Render an update summary panel with tiered urgency.

    Tier rules:

    * Tier 1 (``info``)  — minor/patch behind. Cyan border. Single
      line delta. Operator can skip with one prompt.
    * Tier 2 (``warn``)  — one major behind. Amber border. Lists
      concrete release highlights (value framing). Skip requires
      explicit confirmation.
    * Tier 3 (``critical``) — two+ majors behind OR launcher/image
      majors mismatched. Red border. EOL framing. Skip is gated
      behind ``--no-update-check`` only — the double-prompt no longer
      offers a soft escape.

    The severity payload is computed once in ``offer_updates_for_command``
    and threaded here so the panel and the prompt flow stay in lockstep.
    """
    tier = str((severity or {}).get("tier") or "none")
    update_needed = tier != "none"
    chrome = _TIER_CHROME.get(tier) if update_needed else None

    lines: list[Text] = []
    current = launcher_info.get("current") or "unknown"
    latest = launcher_info.get("latest") or "unknown"

    # ── Header row: version delta, no chrome on Tier 1 ──────────────
    if launcher_info.get("is_newer"):
        header_style = chrome["header_style"] if chrome else "bold yellow"
        lines.append(
            Text(
                f"Launcher: {current}  →  {latest}",
                style=header_style,
            )
        )
    elif tier == "none":
        lines.append(Text(f"Launcher: {current} (up-to-date)", style="green"))

    image = docker_info.get("image") or "unknown"
    if not docker_info.get("image_present"):
        lines.append(Text(f"Docker image missing locally: {image}", style="yellow"))
    elif docker_info.get("needs_update"):
        lines.append(
            Text(
                f"Docker image update available: {image}",
                style=chrome["header_style"] if chrome else "bold yellow",
            )
        )
    elif docker_info.get("image_present") and tier == "none":
        lines.append(Text(f"Docker image: {image} (up-to-date)", style="green"))

    # ── Tier 3: mismatch is the smoking gun — surface it first ─────
    # Stays version-agnostic: states the policy ("different majors is
    # not supported"), not specific symptoms that go stale.
    if tier == _TIER_CRITICAL and bool((severity or {}).get("mismatch")):
        lines.append(Text(""))
        lines.append(
            Text(
                "INCOMPATIBLE COMBINATION DETECTED",
                style="bold red",
            )
        )
        lines.append(
            Text(
                "Your launcher and runtime image are on DIFFERENT major versions. "
                "This combination is NOT supported — commands can fail with errors "
                "that look like new bugs but are version-skew artefacts (CLI "
                "grammar drift, workspace schema mismatches, env-var contract "
                "drift).",
                style="white",
            )
        )

    # ── Tier 1/2/3: factual version delta + loss-aversion motivation ──
    # We do NOT link to per-release notes. Maintaining curated prose
    # per version is a tax that the release process does not pay
    # reliably; pointing at a thin changelog page actively damages
    # conversion ("oh, only minor improvements"). Loss-aversion framing
    # is version-agnostic and works for every release the product will
    # ever ship — see the design comment near the top of this module.
    delta = str((severity or {}).get("delta") or "").strip()
    motivation = str((severity or {}).get("motivation") or "").strip()
    if update_needed and delta:
        lines.append(Text(""))
        lines.append(Text(delta, style="bold white"))
    if update_needed and motivation:
        lines.append(Text(motivation, style="white"))

    # ── Action: a single, unambiguous CTA. One command, copy-pasteable.
    # Per TUI design principle 3 (Progressive Disclosure) the prompt
    # below the panel handles the "yes/no" — the panel itself does not
    # ask, it tells. Per Hormozi: one action, not a menu.
    if update_needed:
        lines.append(Text(""))
        lines.append(
            Text(
                "Run on the host:  adscan update",
                style=chrome["header_style"] if chrome else "bold white",
            )
        )

    # ── Recency tail (kept as is — useful "you've been on this for X days" signal) ──
    recency = get_local_update_recency_summary(ctx.adscan_base_dir)
    recency_message = str(recency.get("message") or "").strip()
    if recency_message:
        lines.append(
            Text(
                recency_message,
                style="yellow" if bool(recency.get("is_stale")) else "dim",
            )
        )
    if bool(recency.get("is_stale")) and tier != _TIER_CRITICAL:
        # Critical tier already conveys "update now" loudly; do not pile on.
        lines.append(
            Text(
                f"Recommendation: update at least every {_STALE_UPDATE_WARNING_DAYS} days.",
                style="bold yellow",
            )
        )

    # ── Title + border, tier-aware ──────────────────────────────────
    if chrome:
        title = f"{chrome['glyph']}  {chrome['title_prefix']}"
        border_style = chrome["border"]
    else:
        title = "Updates"
        border_style = None

    ctx.print_panel(
        Group(*lines),
        title=title,
        border_style=border_style,
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


def offer_updates_for_command(
    ctx: UpdateContext,
    command: str,
    *,
    skip_update_check: bool = False,
    dev_mode: bool = False,
) -> None:
    """Check for launcher/docker updates and offer upgrades (interactive only).

    Args:
        ctx: Update context (host helpers).
        command: The launcher subcommand being executed (``start``, ``ci``, …).
        skip_update_check: When True (set by the user via
            ``--no-update-check``), bypass detection and prompts entirely.
            Reserved for power users with a real reason (mid-engagement,
            airgapped, version pinning). Tier 3 ``critical`` still emits
            a brief reminder so the operator does not forget they are
            running unsupported.
        dev_mode: When True (set by the user via ``--dev`` or by
            existing env-var detection), skip update prompts because the
            local launcher version is intentionally not aligned with
            the published one. Internal development workflows.
    """
    if ctx.is_container_runtime():
        return
    if command in {"update", "upgrade"}:
        return
    if command not in {"start", "ci", "check"}:
        return

    # Explicit user opt-out (--no-update-check). Bypass detection entirely
    # so we don't even hit PyPI/Docker Hub — useful when offline.
    if skip_update_check:
        ctx.print_info_debug(
            "[update] --no-update-check active; skipping detection and prompts."
        )
        return

    # Maintainer dev channel should not show update checks/prompts.
    # CLI `--dev` and env-driven detection are unified here: either path
    # leads to the same skip.
    docker_image = str(ctx.get_docker_image_name() or "").strip().lower()
    if dev_mode or is_dev_update_context(
        os_getenv=ctx.os_getenv, image_name=docker_image
    ):
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

    # Read the version baked into the local image (when present). Used
    # by the severity computation to detect launcher/image major-skew —
    # the v8-launcher-with-v9-image state that the 2026-05-21 telemetry
    # surfaced as the root cause of "unknown" bug reports.
    image_baked_version: str | None = None
    if docker_info.get("image_present"):
        image_baked_version = get_image_baked_version(
            ctx, str(docker_info.get("image") or "")
        )

    severity = compute_update_severity(
        launcher_current=str(launcher_info.get("current") or ""),
        launcher_latest=launcher_info.get("latest"),
        image_present=bool(docker_info.get("image_present")),
        image_needs_update=bool(docker_info.get("needs_update")),
        image_baked_version=image_baked_version,
    )

    if severity["tier"] == "none":
        return

    _render_update_panel(ctx, launcher_info, docker_info, severity=severity)

    is_non_interactive = bool(
        ctx.os_getenv("CI", None)
        or ctx.os_getenv("GITHUB_ACTIONS", None)
        or ctx.os_getenv("CONTINUOUS_INTEGRATION", None)
        or not ctx.sys_stdin_isatty()
    )
    if is_non_interactive:
        ctx.print_info("Non-interactive environment detected; skipping update prompts.")
        recency = get_local_update_recency_summary(ctx.adscan_base_dir)
        if bool(recency.get("is_stale")):
            ctx.print_warning(
                str(recency.get("message") or "Local update cadence looks stale.")
            )
        if severity["tier"] == _TIER_CRITICAL:
            ctx.print_error(
                "Running an unsupported launcher/image combination. Re-run "
                "interactively or run `adscan update` before scanning customer "
                "environments."
            )
        else:
            ctx.print_info(
                "Running with a stale launcher or runtime image can produce "
                "incorrect checks, missed fixes, and older attack coverage."
            )
        ctx.print_instruction("Run: adscan update")
        return

    # ── Interactive update flow ─────────────────────────────────────
    # On Tier 3 (critical / mismatched), the "are you sure?" soft-skip
    # path is disabled — saying No to the prompt now exits the launcher
    # with a clear error rather than continuing into the broken state.
    # The escape hatch is the explicit `--no-update-check` flag, which
    # is the user signalling they understand the risk.
    critical = severity["tier"] == _TIER_CRITICAL

    if launcher_info.get("is_newer"):
        prompt = (
            "Update the launcher now? (REQUIRED — broken combination detected)"
            if critical
            else "Update the launcher now?"
        )
        if ctx.confirm_ask(prompt, True):
            if _update_launcher(ctx, str(launcher_info.get("latest") or "")):
                _restart_into_upgraded_launcher(ctx)
        elif critical:
            ctx.print_error(
                "Refused to continue with a launcher/image major-version mismatch. "
                "Run `adscan update` or pass `--no-update-check` if you accept the risk."
            )
            raise SystemExit(2)
        elif not _confirm_skip_update(ctx, component_label="launcher"):
            if _update_launcher(ctx, str(launcher_info.get("latest") or "")):
                _restart_into_upgraded_launcher(ctx)

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
        elif critical:
            ctx.print_error(
                "Refused to continue with a stale runtime image while a "
                "launcher/image mismatch is active. Run `adscan update` or "
                "pass `--no-update-check`."
            )
            raise SystemExit(2)
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
        _restart_into_upgraded_launcher(ctx)
    elif updated_launcher and not launcher_restart_ready:
        # Upgrade ran but we could not confirm a clean in-process restart.
        _print_launcher_restart_hint(ctx)
    return ok


def handle_update_command(ctx: UpdateContext) -> None:
    """Update both launcher and Docker image (legacy signature)."""
    run_update_command(ctx)
