"""Who this installation is, according to its installed PRO licence (cheap, cached).

Used where identity used to come from the free-typed partner tag (spec § 9.4):
telemetry's partner dimension and the PRO partner-tag start gate (host and
container). A licence that verifies wins over a typed tag; a trial licence
(no partner) also satisfies the start gate, because the licence IS the
identity now. The result is cached by the licence file's size and mtime, so
the per-event cost is one ``stat``. Never raises.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LicensedIdentity:
    """The identity fields an installed, verified licence carries."""

    license_id: str
    edition: str
    partner_tag: str


_CACHE: dict[str, tuple[tuple[int, int], LicensedIdentity | None]] = {}


def installed_licence_identity(directory: Path | None = None) -> LicensedIdentity | None:
    """The identity of the installed PRO licence, or None (absent or not verifying)."""
    try:
        from adscan_core.pro_license.state import ProLicenseStore

        store = ProLicenseStore(directory)
        path = store.licence_path
        try:
            stat = path.stat()
        except OSError:
            return None
        key = str(path)
        signature = (stat.st_size, stat.st_mtime_ns)
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == signature:
            return cached[1]
        licence, _error = store.load_licence()
        identity = (
            LicensedIdentity(licence.license_id, licence.edition, licence.partner_tag)
            if licence is not None
            else None
        )
        _CACHE[key] = (signature, identity)
        return identity
    except Exception:  # noqa: BLE001 - identity lookup must never break a caller
        return None


def clear_cache() -> None:
    """Forget cached lookups (tests, and after installing or removing a licence)."""
    _CACHE.clear()


__all__ = ["LicensedIdentity", "clear_cache", "installed_licence_identity"]
