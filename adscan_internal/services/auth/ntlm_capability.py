"""NTLM capability cache, indexed by ``(realm, dc_host)``.

Some hardened ADs disable NTLM at the policy level
(``Network security: Restrict NTLM`` set to "Deny all").  Probing every time
is wasteful and noisy; a per-realm cache with a TTL is the right trade-off.

The cache is intentionally tri-state:

- ``True``  — NTLM bind succeeded against this DC at least once recently.
- ``False`` — NTLM bind explicitly rejected with a known policy marker.
- ``None``  — unknown (not probed yet, or TTL expired).

The cache is **populated lazily** by ``services/auth/auth_retry.py`` —
this module owns only the storage shape and the policy of "when to forget".
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from adscan_internal.rich_output import mark_sensitive, print_info_debug

# Re-probe NTLM availability after this many seconds even when the cache says
# unavailable — long-running engagements can outlast a GPO rollback.
_DEFAULT_TTL_SECONDS: float = 600.0


@dataclass
class NtlmCapability:
    """Snapshot of one ``(realm, dc_host)`` pair's NTLM availability."""

    available: bool
    last_probed_at: float
    failure_reason: str | None = None


class NtlmCapabilityCache:
    """Process-wide tri-state cache for NTLM bind support per DC."""

    def __init__(self, ttl_seconds: float = _DEFAULT_TTL_SECONDS) -> None:
        self._entries: dict[tuple[str, str], NtlmCapability] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    @staticmethod
    def _key(realm: str, dc_host: str) -> tuple[str, str]:
        return (
            str(realm or "").strip().casefold(),
            str(dc_host or "").strip().casefold(),
        )

    def get(self, realm: str, dc_host: str) -> NtlmCapability | None:
        with self._lock:
            entry = self._entries.get(self._key(realm, dc_host))
            if entry is None:
                return None
            if (time.monotonic() - entry.last_probed_at) > self._ttl:
                # Stale — drop and report as unknown.
                self._entries.pop(self._key(realm, dc_host), None)
                return None
            return entry

    def is_available(self, realm: str, dc_host: str) -> bool | None:
        """Tri-state lookup: ``True`` / ``False`` / ``None`` (unknown)."""
        entry = self.get(realm, dc_host)
        if entry is None:
            return None
        return entry.available

    def mark_available(self, realm: str, dc_host: str) -> None:
        with self._lock:
            self._entries[self._key(realm, dc_host)] = NtlmCapability(
                available=True, last_probed_at=time.monotonic()
            )
        print_info_debug(
            "[ntlm-cap] marked available: "
            f"realm={mark_sensitive(realm, 'domain')} "
            f"dc={mark_sensitive(dc_host, 'host')}"
        )

    def mark_unavailable(
        self, realm: str, dc_host: str, *, reason: str | None = None
    ) -> None:
        with self._lock:
            self._entries[self._key(realm, dc_host)] = NtlmCapability(
                available=False,
                last_probed_at=time.monotonic(),
                failure_reason=reason,
            )
        print_info_debug(
            "[ntlm-cap] marked unavailable: "
            f"realm={mark_sensitive(realm, 'domain')} "
            f"dc={mark_sensitive(dc_host, 'host')} reason={reason or 'unspecified'}"
        )

    def set(self, realm: str, dc_host: str, cap: NtlmCapability) -> None:
        with self._lock:
            self._entries[self._key(realm, dc_host)] = cap


_GLOBAL_CACHE: NtlmCapabilityCache | None = None
_GLOBAL_CACHE_LOCK = threading.Lock()


def get_ntlm_capability_cache() -> NtlmCapabilityCache:
    """Return the process-wide singleton cache."""
    global _GLOBAL_CACHE
    if _GLOBAL_CACHE is None:
        with _GLOBAL_CACHE_LOCK:
            if _GLOBAL_CACHE is None:
                _GLOBAL_CACHE = NtlmCapabilityCache()
    return _GLOBAL_CACHE
