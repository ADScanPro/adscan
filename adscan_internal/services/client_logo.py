"""Client-logo resolution for every ADscan report deliverable — the SSOT.

The operator can co-brand a deliverable with the ASSESSED CLIENT's own logo,
which is placed ALONGSIDE ADscan's mark on the report cover / masthead. This is
distinct from the PRO white-label slot (``logo_uri`` in the premium template),
which REPLACES the ADscan mark entirely and is a separate paid boundary: the
client logo here never suppresses the ADscan mark, it sits next to it.

The feature spans two process boundaries (see ``CLAUDE.md`` § "Architecture and
Deployment Model"): the operator's logo file lives on the HOST, the report
renders INSIDE the container. The launcher copies the selected file into the
mounted ``~/.adscan`` volume (host path via ``adscan_launcher``), and this
module — running in the container — resolves it back through the ADscan home
and embeds it as a ``data:`` URI so it survives the HTML→PDF Chromium render
with no external URL (CSP- and offline-safe).

Persistence: the chosen logo is stored under :data:`CLIENT_LOGO_CONFIG_KEY` in
``~/.adscan/config.json`` (the shared operator-preferences file), so a logo
picked once is reused on every later ``deliver`` / ``ci`` run without
re-selecting it. A relative value is stored (e.g. ``branding/acme.png``) and
resolved against the container's ADscan home, which keeps the record valid
across the host/container path split.

LITE-safety: this module imports nothing from ``adscan_internal.pro`` and
nothing beyond the standard library plus ``adscan_core``. Both the LITE
exposure report and the PRO deliverable kit consume it.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from adscan_core.paths import get_adscan_home_dir
from adscan_core.rich_output import print_exception

#: The config.json key holding the persisted client logo path.
CLIENT_LOGO_CONFIG_KEY = "client_logo"

#: Sub-directory under the ADscan home where the launcher stages a copied logo.
#: The launcher writes into the host side of this dir; the container reads the
#: same bytes through the bind mount.
CLIENT_LOGO_DIRNAME = "branding"

#: Image suffixes we accept for a client logo, mapped to their data-URI MIME
#: type. SVG stays vector (sharp at any print size); the rasters embed as-is.
_LOGO_MIME_BY_SUFFIX: dict[str, str] = {
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
}

#: The suffixes an operator may pass, for validation / picker filters.
SUPPORTED_LOGO_SUFFIXES: tuple[str, ...] = tuple(_LOGO_MIME_BY_SUFFIX.keys())


def _config_path() -> Path:
    """Return the shared operator-preferences file path (container-side)."""
    return get_adscan_home_dir() / "config.json"


def is_supported_logo_suffix(path: str | os.PathLike[str]) -> bool:
    """Return whether ``path`` has a supported image suffix."""
    return Path(path).suffix.lower() in _LOGO_MIME_BY_SUFFIX


def encode_client_logo_data_uri(path: str | os.PathLike[str] | None) -> str:
    """Return the logo file as a ``data:`` URI, or ``""`` when unavailable.

    Reads the file at ``path`` and base64-encodes it with the MIME type derived
    from its suffix, so the logo travels inside the HTML and needs no external
    reference at render time (CSP- and offline-safe). An unsupported suffix,
    missing file, or read error yields ``""`` — the logo is cosmetic and must
    never break a render.

    Args:
        path: Filesystem path to the logo image.

    Returns:
        ``data:<mime>;base64,…`` or ``""``.
    """
    if not path:
        return ""
    file_path = Path(path)
    mime = _LOGO_MIME_BY_SUFFIX.get(file_path.suffix.lower())
    if mime is None:
        return ""
    try:
        if not file_path.is_file():
            return ""
        raw = file_path.read_bytes()
    except OSError:
        return ""
    if not raw:
        return ""
    return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"


def _resolve_existing_path(value: str) -> str:
    """Resolve a stored/flag path value to an existing file, or ``""``.

    A value may be absolute (``/opt/adscan/branding/acme.png``) or relative to
    the ADscan home (``branding/acme.png`` — how the launcher forwards a staged
    logo, which keeps the record valid across the host/container path split).
    Both are tried; a relative path is also tried as-is (relative to the current
    directory) as a last resort for a directly-invoked flag.
    """
    if not value:
        return ""
    candidate = Path(value)
    if candidate.is_absolute():
        return str(candidate) if candidate.is_file() else ""
    home_relative = get_adscan_home_dir() / value
    if home_relative.is_file():
        return str(home_relative)
    if candidate.is_file():
        return str(candidate.resolve())
    return ""


def load_client_logo_setting(*, config_path: Path | None = None) -> str:
    """Return the persisted client-logo path string, or ``""``.

    Reads :data:`CLIENT_LOGO_CONFIG_KEY` from ``config.json``. Never raises;
    returns ``""`` when the file is missing, unreadable, or lacks the key.
    """
    path = config_path or _config_path()
    try:
        with open(path, encoding="utf-8") as handle:
            data: dict[str, Any] = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return ""
    if not isinstance(data, dict):
        return ""
    value = data.get(CLIENT_LOGO_CONFIG_KEY)
    return value.strip() if isinstance(value, str) else ""


def save_client_logo_setting(value: str, *, config_path: Path | None = None) -> None:
    """Persist the client-logo path under :data:`CLIENT_LOGO_CONFIG_KEY`.

    Merges into ``config.json``, preserving every other key. Never raises — a
    preference-save failure must not interrupt a delivery.

    Args:
        value: The path to store. Prefer a home-relative value
            (``branding/acme.png``) so it stays valid across host/container.
    """
    path = config_path or _config_path()
    try:
        try:
            with open(path, encoding="utf-8") as handle:
                data: dict[str, Any] = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        data[CLIENT_LOGO_CONFIG_KEY] = str(value)
        os.makedirs(path.parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001 — cosmetic preference; never break delivery
        print_exception(exception=exc)


def clear_client_logo_setting(*, config_path: Path | None = None) -> None:
    """Remove the persisted client logo, so later runs render only ADscan's mark."""
    path = config_path or _config_path()
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return
    if not isinstance(data, dict) or CLIENT_LOGO_CONFIG_KEY not in data:
        return
    data.pop(CLIENT_LOGO_CONFIG_KEY, None)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
    except OSError as exc:
        print_exception(exception=exc)


def resolve_client_logo_path(
    explicit: str | None = None, *, config_path: Path | None = None
) -> str:
    """Resolve the client-logo file path to use, or ``""``.

    Precedence: an ``explicit`` value (the ``--client-logo`` flag) first, then
    the persisted config value. Each is resolved to an existing file (absolute
    or home-relative). Returns ``""`` when nothing resolves.
    """
    for value in (explicit, load_client_logo_setting(config_path=config_path)):
        if not value:
            continue
        resolved = _resolve_existing_path(str(value).strip())
        if resolved:
            return resolved
    return ""


def resolve_client_logo_data_uri(
    explicit: str | None = None, *, config_path: Path | None = None
) -> str:
    """Resolve the client logo and return it as a ``data:`` URI, or ``""``.

    The single call the report builders make: it resolves the path
    (:func:`resolve_client_logo_path`) and encodes it
    (:func:`encode_client_logo_data_uri`). ``""`` means "render only ADscan's
    mark", which every template already handles.
    """
    return encode_client_logo_data_uri(
        resolve_client_logo_path(explicit, config_path=config_path)
    )


__all__ = (
    "CLIENT_LOGO_CONFIG_KEY",
    "CLIENT_LOGO_DIRNAME",
    "SUPPORTED_LOGO_SUFFIXES",
    "clear_client_logo_setting",
    "encode_client_logo_data_uri",
    "is_supported_logo_suffix",
    "load_client_logo_setting",
    "resolve_client_logo_data_uri",
    "resolve_client_logo_path",
    "save_client_logo_setting",
)
