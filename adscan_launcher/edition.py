"""Which ADscan edition this host runs: the PRO licence decides (founder decision, 2026-11-12).

One place answers "LITE or PRO, and from which image?" for every launcher
command (``start``, ``ci``, ``install``, ``update``, the deliverables):

1. ``ADSCAN_DOCKER_IMAGE`` / ``--image`` (advanced and development override)
   always wins, and the image name decides the edition.
2. ``--lite`` (``ADSCAN_LAUNCH_EDITION=lite``) or a persisted ``adscan config edition
   lite`` forces LITE.
3. An installed PRO licence that allows new assessments means PRO, pulled from
   ``registry.adscanpro.com`` with this installation's own key (no stored
   password, no GitHub account).
4. A PRO licence that no longer allows assessments (revoked, released, expired,
   not verifiable) falls back to LITE with ONE line saying why and who to
   contact, never silently. Workspaces are untouched and stay readable.
5. No licence: LITE, silently.

The development channel (``--dev``) keeps its own images and is not decided
here. The licence status is read through the PRO licence status SSOT
(:func:`adscan_core.pro_license.evaluation.check_pro_license`), cached per
process by the licence file's size and mtime.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adscan_core.outbound_links import ADSCAN_REGISTRY_HOST

#: The licence-authorised registry and its PRO repository.
PRO_REGISTRY_HOST = ADSCAN_REGISTRY_HOST
PRO_REPOSITORY = "adscan/pro"
PRO_CHANNEL_TAG = "stable"
PRO_IMAGE = f"{PRO_REGISTRY_HOST}/{PRO_REPOSITORY}:{PRO_CHANNEL_TAG}"

#: Where PRO was published before the licence-authorised registry. During the
#: 30-day parallel run a host that is ALREADY logged in to one of them (an
#: existing PRO user onboarded with a GitHub account) still falls back to it
#: when the new registry cannot be reached, up to and including
#: :data:`LEGACY_PRO_SUNSET`. After that date the publisher stops pushing there,
#: so the launcher stops falling back too and never runs a stale image
#: (``license_server/deploy/registry/RUNBOOK.md`` § Retire GHCR and Docker Hub).
#: The date matches ``ADSCAN_PRO_LEGACY_SUNSET`` in ``scripts/registry.env``
#: (locked by ``tests/unit/test_registry_targets_ssot.py``).
LEGACY_PRO_SUNSET = "2026-12-31"
LEGACY_PRO_IMAGES: tuple[tuple[str, str], ...] = (
    ("ghcr.io", "ghcr.io/adscanpro/adscan-pro:latest"),
    ("https://index.docker.io/v1/", "adscan/adscan-pro:latest"),
)
LEGACY_FALLBACK_ENV = "ADSCAN_PRO_LEGACY_REGISTRY_FALLBACK"

#: ``--lite`` sets this for the launcher process (launcher-only, never forwarded).
#: Not ``ADSCAN_EDITION``: that one is the engine's tier variable (adscan_core.tier).
EDITION_ENV = "ADSCAN_LAUNCH_EDITION"
EDITION_LITE = "lite"
EDITION_PRO = "pro"
EDITION_AUTO = "auto"
EDITION_STATE_FILENAME = "launcher-edition.json"

#: Why the edition was chosen (shown by ``adscan --version`` and in telemetry).
SOURCE_IMAGE_OVERRIDE = "image_override"
SOURCE_LITE_FLAG = "lite_flag"
SOURCE_CONFIG = "config"
SOURCE_LICENCE = "licence"
SOURCE_LICENCE_INACTIVE = "licence_inactive"
SOURCE_NO_LICENCE = "no_licence"


@dataclass(frozen=True)
class EditionDecision:
    """The edition this launch runs and why."""

    edition: str
    source: str
    #: One operator line when a licence is present but cannot run PRO.
    notice: str = ""
    licence_state: str = ""

    @property
    def is_pro(self) -> bool:
        return self.edition == EDITION_PRO


# ── Persisted preference (``adscan config edition``) ─────────────────────────


def _state_file() -> Path:
    from adscan_core.paths import get_state_dir

    return get_state_dir() / EDITION_STATE_FILENAME


def persisted_edition() -> str:
    """``lite`` when the operator pinned LITE, else ``auto`` (the licence decides)."""
    try:
        data = json.loads(_state_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return EDITION_AUTO
    value = str(data.get("edition") or "").strip().lower() if isinstance(data, dict) else ""
    return EDITION_LITE if value == EDITION_LITE else EDITION_AUTO


def set_persisted_edition(value: str) -> str:
    """Persist ``lite`` or ``auto``; return what was stored."""
    value = str(value or "").strip().lower()
    if value not in (EDITION_LITE, EDITION_AUTO):
        raise ValueError("The edition is 'lite' or 'auto'.")
    path = _state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"edition": value}) + "\n", encoding="utf-8")
    tmp.replace(path)
    clear_cache()
    return value


# ── Licence status (cached) ──────────────────────────────────────────────────

_STATUS_CACHE: dict[str, tuple[tuple[int, int], Any]] = {}


def _licence_status() -> Any | None:
    """The PRO licence status, or None when no licence file exists. Never raises."""
    try:
        from adscan_core.pro_license.evaluation import check_pro_license
        from adscan_core.pro_license.state import ProLicenseStore

        store = ProLicenseStore()
        try:
            stat = store.licence_path.stat()
        except OSError:
            return None
        key = str(store.licence_path)
        signature = (stat.st_size, stat.st_mtime_ns)
        cached = _STATUS_CACHE.get(key)
        if cached is not None and cached[0] == signature:
            return cached[1]
        status = check_pro_license(store)
        _STATUS_CACHE[key] = (signature, status)
        return status
    except Exception:  # noqa: BLE001 - the edition decision must never break a launch
        return None


def clear_cache() -> None:
    """Forget the cached licence status (after activate, deactivate or a check-in)."""
    _STATUS_CACHE.clear()
    global _NOTICE_SHOWN
    _NOTICE_SHOWN = False


def refresh_licence_status() -> None:
    """Run the licence check-in now (bounded, never raises), so a pull follows the current verdict.

    ``adscan update`` and the post-activation download call it first: a licence
    revoked since the last launch then selects LITE (with the one-line notice)
    instead of asking the registry, which would refuse anyway. Whether anything is
    sent is decided by the licence channel (``client.launch_check_in``: no online
    licence, an engagement licence or an Enterprise process send nothing; an
    online licence checks in even under offline mode).
    """
    try:
        from adscan_core.pro_license import client
        from adscan_core.pro_license.state import ProLicenseStore

        store = ProLicenseStore()
        if store.has_licence_file():
            result = client.launch_check_in(store)
            if result is not None and result.error is not None:
                from adscan_core import telemetry
                from adscan_core.rich_output import print_exception

                telemetry.capture_exception(result.error)
                print_exception(exception=result.error)
    except Exception as exc:  # noqa: BLE001 - a check-in never blocks an update
        from adscan_core import telemetry
        from adscan_core.rich_output import print_exception

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    finally:
        clear_cache()


def _inactive_notice(status: Any) -> str:
    from adscan_core.outbound_links import ADSCAN_CONTACT_EMAIL

    state = str(getattr(status, "state", "") or "")
    why = {
        "revoked": "was revoked",
        "expired": "has ended",
        "invalid": "cannot be verified on this machine",
        "clock_rollback": "cannot be checked because this machine's clock moved backwards",
        "not_yet_valid": "is not valid yet",
    }.get(state, "does not allow new assessments right now")
    return (
        f"Your ADscan PRO licence {why}, so this machine runs ADscan LITE. Your workspaces stay "
        f"available. To restore PRO, contact ADscan at {ADSCAN_CONTACT_EMAIL}."
    )


def _edition_from_image(image: str) -> str:
    lowered = image.lower()
    if PRO_REGISTRY_HOST in lowered or "adscan-pro" in lowered or lowered.rsplit("/", 1)[-1].startswith("pro:"):
        return EDITION_PRO
    return EDITION_LITE


def resolve_edition() -> EditionDecision:
    """Decide the edition for this launch (see the module docstring for the order)."""
    explicit = os.getenv("ADSCAN_DOCKER_IMAGE", "").strip()
    if explicit:
        return EditionDecision(_edition_from_image(explicit), SOURCE_IMAGE_OVERRIDE)
    if os.getenv(EDITION_ENV, "").strip().lower() == EDITION_LITE:
        return EditionDecision(EDITION_LITE, SOURCE_LITE_FLAG)
    if persisted_edition() == EDITION_LITE:
        return EditionDecision(EDITION_LITE, SOURCE_CONFIG)
    status = _licence_status()
    if status is None:
        return EditionDecision(EDITION_LITE, SOURCE_NO_LICENCE)
    state = str(getattr(status, "state", "") or "")
    if state == "missing":
        return EditionDecision(EDITION_LITE, SOURCE_NO_LICENCE, licence_state=state)
    if bool(getattr(status, "scans_allowed", False)):
        return EditionDecision(EDITION_PRO, SOURCE_LICENCE, licence_state=state)
    return EditionDecision(EDITION_LITE, SOURCE_LICENCE_INACTIVE, notice=_inactive_notice(status), licence_state=state)


_NOTICE_SHOWN = False


def announce_fallback_once(decision: EditionDecision) -> None:
    """Print the licence-inactive line once per process (never silent, never repeated)."""
    global _NOTICE_SHOWN
    if not decision.notice or _NOTICE_SHOWN:
        return
    _NOTICE_SHOWN = True
    try:
        from adscan_core.rich_output import print_warning

        print_warning(decision.notice)
    except Exception:  # noqa: BLE001
        return


def _legacy_fallback_enabled(today: str | None = None) -> bool:
    """The opt-out is off and today (UTC calendar date) is not past the sunset."""
    if os.getenv(LEGACY_FALLBACK_ENV, "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    from datetime import datetime, timezone

    current = today or datetime.now(timezone.utc).date().isoformat()
    return current <= LEGACY_PRO_SUNSET


def legacy_override_notice(image: str, *, today: str | None = None) -> str | None:
    """One line for an ``ADSCAN_DOCKER_IMAGE``/``--image`` that names a retired PRO repository.

    After :data:`LEGACY_PRO_SUNSET` nothing new is published to GHCR or Docker
    Hub for PRO, so a pinned legacy reference keeps running an image that never
    updates. The local development tag (``:edge``) is not a publication and is
    left alone. None when there is nothing to say.
    """
    from datetime import datetime, timezone

    reference = str(image or "").strip()
    repository, _, tag = reference.rpartition(":") if ":" in reference.rsplit("/", 1)[-1] else (reference, "", "")
    legacy_repositories = {legacy.rsplit(":", 1)[0] for _registry, legacy in LEGACY_PRO_IMAGES}
    if repository not in legacy_repositories or tag == "edge":
        return None
    current = today or datetime.now(timezone.utc).date().isoformat()
    if current <= LEGACY_PRO_SUNSET:
        return None
    return (
        f"ADSCAN_DOCKER_IMAGE (or --image) names {repository}, which stopped receiving ADscan PRO updates on "
        f"{LEGACY_PRO_SUNSET}. Remove it so your licence selects ADscan PRO from {PRO_REGISTRY_HOST}."
    )


_LEGACY_OVERRIDE_SHOWN = False


def announce_legacy_override_once(image: str) -> None:
    """Print :func:`legacy_override_notice` once per process (never raises)."""
    global _LEGACY_OVERRIDE_SHOWN
    notice = legacy_override_notice(image)
    if not notice or _LEGACY_OVERRIDE_SHOWN:
        return
    _LEGACY_OVERRIDE_SHOWN = True
    try:
        from adscan_core.rich_output import print_warning

        print_warning(notice)
    except Exception:  # noqa: BLE001
        return


def user_docker_config_dir() -> Path:
    """The operator's own Docker client config directory (``$DOCKER_CONFIG`` or ``~/.docker``)."""
    config_dir = os.getenv("DOCKER_CONFIG", "").strip()
    return Path(config_dir) if config_dir else Path.home() / ".docker"


def _logged_in_registries() -> set[str]:
    """Registries the operator's own Docker config holds credentials for (names only, never secrets)."""
    path = user_docker_config_dir() / "config.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    names: set[str] = set()
    for section in ("auths", "credHelpers"):
        value = data.get(section) if isinstance(data, dict) else None
        if isinstance(value, dict):
            names.update(str(k) for k in value)
    return names


def pro_image_candidates() -> list[str]:
    """PRO images in pull order: the licence-authorised registry, then legacy ones the host is logged in to."""
    candidates = [PRO_IMAGE]
    if _legacy_fallback_enabled():
        logged_in = _logged_in_registries()
        for registry, image in LEGACY_PRO_IMAGES:
            if registry in logged_in or registry.replace("https://", "").split("/")[0] in logged_in:
                candidates.append(image)
    return candidates


def is_pro_registry_image(image: str) -> bool:
    """True when ``image`` lives on the licence-authorised registry."""
    return str(image or "").strip().lower().startswith(PRO_REGISTRY_HOST + "/")


__all__ = [
    "EDITION_AUTO",
    "EDITION_ENV",
    "EDITION_LITE",
    "EDITION_PRO",
    "LEGACY_PRO_IMAGES",
    "LEGACY_PRO_SUNSET",
    "PRO_IMAGE",
    "PRO_REGISTRY_HOST",
    "EditionDecision",
    "announce_fallback_once",
    "announce_legacy_override_once",
    "clear_cache",
    "is_pro_registry_image",
    "legacy_override_notice",
    "persisted_edition",
    "pro_image_candidates",
    "resolve_edition",
    "user_docker_config_dir",
    "set_persisted_edition",
]
