"""Licence identity carried by telemetry when a PRO licence is installed.

The PRO licence is the telemetry identity of a PRO install (founder decision
2026-11-12). We issue the licence, so we know whose it is, and each
installation is its own seat. The user never types anything: the CLI no
longer asks for a partner tag, and no environment variable or file sets one.
Telemetry carries three fields taken from the installed, signature-verified
licence:

* ``licence_grant_id`` — the grant (``g-…``): one per commercial agreement,
  shared by every seat of that agreement. It is also the PostHog group key
  (group type ``licence``), so analytics aggregate by licence.
* ``licence_installation_id`` — the installation the licence is bound to
  (``in-…``): one per seat (an engineer's machine, an unattended agent host).
* ``partner_tag`` — OUR label for the licence (``potech-pro``), set by us on
  the licence server and signed into the document. A company or engagement
  label we chose, not something the holder typed.

NEVER the holder's display name (``customer``) or an email. The licence
document carries ``customer`` for the operator's own ``adscan license
status``; it must never reach a payload. The allow-list below
is the only shape this module can emit, and
``tests/unit/core/test_licence_telemetry_identity.py`` locks it.

The same names are used by the licence server's own lifecycle events
(activation, check-in, refresh, release, revocation), so client and server
events join on one PostHog group key.

No licence (LITE, or a legacy PRO install never activated) means no fields:
that telemetry stays pseudonymous exactly as before. Telemetry being off is
enforced upstream by every sender; this module only answers "who".

Cost: the parsed licence is cached by the file's size and mtime, so the
per-event cost is one ``stat``. Never raises.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from adscan_core.partner_tag_format import validate_partner_tag

#: Event / person property names. Shared contract with the licence server.
LICENCE_GRANT_ID_PROPERTY = "licence_grant_id"
LICENCE_INSTALLATION_ID_PROPERTY = "licence_installation_id"
PARTNER_TAG_PROPERTY = "partner_tag"

#: PostHog group type whose key is the grant id.
LICENCE_GROUP_TYPE = "licence"

#: The ONLY keys this module may emit. Anything naming a person or company is
#: structurally excluded.
LICENCE_TELEMETRY_KEYS = frozenset(
    {LICENCE_GRANT_ID_PROPERTY, LICENCE_INSTALLATION_ID_PROPERTY, PARTNER_TAG_PROPERTY}
)

_ID_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")

_CACHE: dict[str, tuple[tuple[int, int], dict[str, str]]] = {}


def _opaque(value: object, prefix: str) -> str:
    """Return ``value`` only when it is a well-formed opaque id with ``prefix``."""
    text = str(value or "").strip()
    if not text.startswith(prefix) or len(text) > 64:
        return ""
    body = text[len(prefix) :]
    # Exactly the shape the licence server issues and the sessions viewer
    # accepts: lowercase ASCII letters and digits.
    if not body or not all(ch in _ID_ALPHABET for ch in body):
        return ""
    return text


def licence_telemetry_fields(
    directory: Path | None = None,
    *,
    trusted_keys: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """The opaque licence identifiers for telemetry, or ``{}`` without a licence.

    Args:
        directory: Licence directory (default: the shared licence dir).
        trusted_keys: Verification keys override, for tests only.

    Returns:
        ``{"licence_grant_id": "g-…", "licence_installation_id": "in-…",
        "partner_tag": "…"}`` when a licence that verifies is installed (a key
        is omitted when the document lacks it or it is malformed), else ``{}``.
    """
    try:
        from adscan_core.pro_license.state import ProLicenseStore

        store = ProLicenseStore(directory)
        path = store.licence_path
        try:
            stat = path.stat()
        except OSError:
            return {}
        key = f"{path}|{sorted(trusted_keys.items()) if trusted_keys else ''}"
        signature = (stat.st_size, stat.st_mtime_ns)
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == signature:
            return dict(cached[1])
        licence, _error = store.load_licence(trusted_keys=trusted_keys)
        fields: dict[str, str] = {}
        if licence is not None:
            grant = _opaque(licence.grant_id, "g-")
            installation = _opaque(licence.installation_id, "in-")
            if grant:
                fields[LICENCE_GRANT_ID_PROPERTY] = grant
            if installation:
                fields[LICENCE_INSTALLATION_ID_PROPERTY] = installation
            tag = str(licence.partner_tag or "").strip()
            if tag and validate_partner_tag(tag):
                fields[PARTNER_TAG_PROPERTY] = tag
        _CACHE[key] = (signature, fields)
        return dict(fields)
    except Exception:  # noqa: BLE001 - identity lookup must never break telemetry
        return {}


def licence_group(fields: Mapping[str, str]) -> dict[str, str]:
    """PostHog ``$groups`` value for ``fields`` (empty without a grant id)."""
    grant = fields.get(LICENCE_GRANT_ID_PROPERTY, "")
    return {LICENCE_GROUP_TYPE: grant} if grant else {}


def clear_cache() -> None:
    """Forget cached lookups (tests, and after installing or removing a licence)."""
    _CACHE.clear()


__all__ = [
    "LICENCE_GRANT_ID_PROPERTY",
    "LICENCE_GROUP_TYPE",
    "LICENCE_INSTALLATION_ID_PROPERTY",
    "LICENCE_TELEMETRY_KEYS",
    "PARTNER_TAG_PROPERTY",
    "clear_cache",
    "licence_group",
    "licence_telemetry_fields",
]
