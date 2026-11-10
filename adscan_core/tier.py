"""Tier (LITE vs PRO) detection — single source of truth.

ADscan ships in two tiers:

- **LITE**: open-source community engine. ``adscan_internal.pro`` is absent.
- **PRO**: closed-source. Adds the client deliverable kit.

This module exposes a tiny, dependency-light API that every other module
should consult instead of importing ``adscan_internal.pro`` directly:

- :func:`is_pro` — True when the PRO package is importable.
- :func:`tier_name` — "PRO" or "LITE".
- :func:`is_enterprise_edition` — True on the Enterprise appliance / PoV, the
  only edition that requires a signed license file
  (:mod:`adscan_core.enterprise_license`).

Both calls are cached after the first lookup so callers do not pay an
import-resolution cost on every render.

Compatibility note:
    LITE/runtime code MUST NOT import ``adscan_internal.pro`` directly.
    Use :func:`is_pro` instead — the import is performed defensively here
    and any failure is treated as "LITE".
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

#: Environment marker the appliance sets for every process it runs (the Celery
#: worker exports it, the launcher forwards it into the scan container, the web
#: backend reads it from its compose environment).
EDITION_ENV = "ADSCAN_EDITION"
ENTERPRISE_EDITION = "enterprise"

#: Marker file baked into an engine image built with
#: ``build_docker_pro_image.sh --enterprise`` (Linux container image only). A
#: file rather than an image ENV because ``docker run -e`` can override an ENV;
#: nothing in the environment can remove this marker.
IMAGE_EDITION_MARKER = Path("/usr/local/share/adscan/edition")


@lru_cache(maxsize=1)
def is_pro() -> bool:
    """Return ``True`` when the PRO runtime is available.

    Detection is by import probe: if ``adscan_internal.pro`` can be
    imported, we are PRO. Any failure (ImportError, ModuleNotFoundError,
    or any unexpected error during import) yields ``False`` — the LITE
    default is always safe.

    The result is cached for the lifetime of the process. Tests that
    need to flip the value must clear the cache via
    ``is_pro.cache_clear()``.
    """
    try:
        import importlib

        importlib.import_module("adscan_internal.pro")
        return True
    except Exception:  # noqa: BLE001 — any failure means "not PRO"
        return False


@lru_cache(maxsize=1)
def tier_name() -> str:
    """Return ``"PRO"`` or ``"LITE"`` based on :func:`is_pro`."""
    return "PRO" if is_pro() else "LITE"


def _image_marker_says_enterprise(marker: Path) -> bool:
    from adscan_core.pal.platform import is_posix

    if not is_posix():
        return False
    try:
        return marker.read_text(encoding="utf-8").strip().lower() == ENTERPRISE_EDITION
    except OSError:
        return False


def is_enterprise_edition(
    *, env: dict[str, str] | None = None, marker: Path | None = None
) -> bool:
    """Return True when this process runs the Enterprise edition.

    Enterprise is a deployment edition of the PRO engine (the appliance and
    its PoV), so it cannot be inferred from an import probe like
    :func:`is_pro`. It is an explicit marker, and markers only ever ADD the
    edition: ``ADSCAN_EDITION=enterprise`` in the environment, or the marker
    file baked into an Enterprise engine image. Neither an empty variable nor
    a different value turns an Enterprise image back into PRO. LITE and PRO
    without a marker never consult a license.

    Args:
        env: Environment mapping to read (tests). Defaults to ``os.environ``.
        marker: Marker file path (tests). Defaults to :data:`IMAGE_EDITION_MARKER`.
    """
    source = os.environ if env is None else env
    if str(source.get(EDITION_ENV, "")).strip().lower() == ENTERPRISE_EDITION:
        return True
    return _image_marker_says_enterprise(marker or IMAGE_EDITION_MARKER)


__all__ = (
    "EDITION_ENV",
    "ENTERPRISE_EDITION",
    "IMAGE_EDITION_MARKER",
    "is_enterprise_edition",
    "is_pro",
    "tier_name",
)
