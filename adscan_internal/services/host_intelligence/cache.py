"""Workspace-scoped cache of :class:`HostFingerprint` per host IP.

Persists to ``<workspace>/domains/<domain>/host_intel.json``. TTL is
configurable (default 1 hour). A per-IP :class:`asyncio.Lock` prevents
concurrent callers from fingerprinting the same host twice during a
single event-loop session.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from adscan_internal import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.services.host_intelligence.models import (
    DetectedProduct,
    HostFingerprint,
)
from adscan_internal.services.smb_transport import SMBConfig
from adscan_core.rich_output import print_exception


class _FingerprintProto(Protocol):
    async def fingerprint(self, config: SMBConfig) -> HostFingerprint: ...


class HostIntelligenceCache:
    """Per-workspace fingerprint cache with TTL and asyncio locking."""

    _FILENAME = "host_intel.json"

    def __init__(self, cache_dir: str | Path) -> None:
        self._dir = Path(cache_dir)
        self._path = self._dir / self._FILENAME
        self._data: dict = self._load()
        self._locks: dict[str, asyncio.Lock] = {}
        # Domain to which fingerprints in this cache should be attributed
        # in the defensive_posture inventory writer. ``None`` disables the
        # parallel writer (the operational cache file is always saved).
        self._domain: str | None = None
        # Optional ``{target_ip: dns_name}`` so the writer can emit a
        # human-readable host id even when SID/GUID are unavailable.
        self._dns_by_ip: dict[str, str] = {}

    def bind_domain(self, domain: str | None) -> None:
        """Attach a domain to this cache for defensive-posture writing.

        The cache itself is workspace-scoped (one file per workspace),
        but the inventory artefact is per-domain. Callers (the shell
        / scan orchestrator) bind the active domain so each save also
        emits ``<workspace>/domains/<domain>/inventory/defensive_posture.json``.
        """
        if domain:
            self._domain = domain.strip().rstrip(".").lower()
        else:
            self._domain = None

    def record_dns_name(self, target_ip: str, dns_name: str | None) -> None:
        """Associate a DNS name with a target IP for inventory output."""
        if target_ip and dns_name:
            self._dns_by_ip[target_ip] = dns_name

    # ---------------------------------------------------------------- I/O

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except Exception:  # noqa: BLE001
                pass
        return {"hosts": {}}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._data, indent=2, default=str))
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[host_intel_cache] save error: {exc}")
        # Mirror the cache state into the per-domain Defensive Posture
        # inventory file consumed by the web app. Best-effort — the
        # writer never raises (it captures to telemetry on failure).
        self._flush_defensive_posture_inventory()

    def _flush_defensive_posture_inventory(self) -> None:
        if not self._domain:
            return
        try:
            from adscan_internal.services.host_intelligence.inventory_writer import (
                write_defensive_posture_inventory,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return
        # Cache stores by IP; we use IP as the host_object_id fallback
        # because SID / objectGUID are not visible at this layer. The
        # backend ingester treats host_object_id as opaque so this
        # remains stable across runs.
        fingerprints: dict[str, HostFingerprint] = {}
        for ip, raw in (self._data.get("hosts") or {}).items():
            try:
                fingerprints[ip] = self._deserialize(raw)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                continue
        # The cache file lives at ``<workspace>/host_intel.json`` — the
        # workspace root is its parent directory.
        workspace_root = self._dir
        write_defensive_posture_inventory(
            workspace_root,
            self._domain,
            fingerprints,
            dns_name_lookup=dict(self._dns_by_ip),
        )

    # ---------------------------------------------------------------- API

    def _lock_for(self, target_ip: str) -> asyncio.Lock:
        lk = self._locks.get(target_ip)
        if lk is None:
            lk = asyncio.Lock()
            self._locks[target_ip] = lk
        return lk

    def get_cached(self, target_ip: str) -> HostFingerprint | None:
        """Return the cached fingerprint for ``target_ip`` (no TTL check)."""
        raw = self._data.get("hosts", {}).get(target_ip)
        if not raw:
            return None
        return self._deserialize(raw)

    def cache_age_seconds(self, target_ip: str) -> int | None:
        """Return age of the cached entry in seconds, or ``None`` if absent."""
        raw = self._data.get("hosts", {}).get(target_ip)
        if not raw:
            return None
        try:
            return int(time.time() - float(raw.get("_cached_at", 0)))
        except Exception:  # noqa: BLE001
            return None

    async def get_or_fingerprint(
        self,
        *,
        config: SMBConfig,
        fp_service: _FingerprintProto,
        force_refresh: bool = False,
        ttl_seconds: int = 3600,
    ) -> HostFingerprint:
        """Return cached fingerprint when fresh, otherwise run a new one.

        Args:
            config: SMB config for the target host.
            fp_service: Object exposing ``fingerprint(config)``.
            force_refresh: When True, bypass the TTL check.
            ttl_seconds: How long a cache entry is considered fresh.

        Returns:
            Fresh or cached :class:`HostFingerprint`.
        """
        target_ip = config.target_ip
        async with self._lock_for(target_ip):
            if not force_refresh:
                age = self.cache_age_seconds(target_ip)
                if age is not None and age < ttl_seconds:
                    cached = self.get_cached(target_ip)
                    if cached is not None:
                        print_info_debug(
                            f"[host_intel_cache] hit for {target_ip} (age={age}s)"
                        )
                        return cached
            fp = await fp_service.fingerprint(config)
            self._store(fp)
            return fp

    async def invalidate(self, target_ip: str) -> None:
        """Drop the cached entry for ``target_ip`` (if any)."""
        async with self._lock_for(target_ip):
            hosts = self._data.setdefault("hosts", {})
            if target_ip in hosts:
                hosts.pop(target_ip, None)
                self._save()

    # -------------------------------------------------------- serialization

    def _store(self, fp: HostFingerprint) -> None:
        hosts = self._data.setdefault("hosts", {})
        hosts[fp.target_ip] = self._serialize(fp)
        self._save()

    @staticmethod
    def _serialize(fp: HostFingerprint) -> dict:
        # PPL / lsass extras live on LsassHostFingerprint (subclass).
        # Read defensively via getattr so the base class stays valid.
        return {
            "_cached_at": time.time(),
            "target_ip": fp.target_ip,
            "defender_rtp": fp.defender_rtp,
            "elapsed_s": fp.elapsed_s,
            "error": fp.error,
            "products": [asdict(p) for p in fp.products],
            "ppl_enabled": getattr(fp, "ppl_enabled", None),
            "ppl_level": getattr(fp, "ppl_level", None),
            "lsass_pid": getattr(fp, "lsass_pid", None),
        }

    @staticmethod
    def _deserialize(raw: dict) -> HostFingerprint:
        products = [DetectedProduct(**p) for p in raw.get("products", [])]
        # When LSASS extras were captured, return the extended subclass
        # so the inventory writer can surface ppl_enabled / lsass_pid.
        if "ppl_enabled" in raw or "ppl_level" in raw or "lsass_pid" in raw:
            try:
                from adscan_internal.services.exploitation.host_fingerprint_service import (
                    LsassHostFingerprint,
                )
            except Exception:  # noqa: BLE001
                LsassHostFingerprint = None  # type: ignore[assignment]
            if LsassHostFingerprint is not None:
                return LsassHostFingerprint(
                    target_ip=raw.get("target_ip", ""),
                    products=products,
                    defender_rtp=bool(raw.get("defender_rtp", True)),
                    elapsed_s=float(raw.get("elapsed_s", 0.0)),
                    error=raw.get("error"),
                    ppl_enabled=bool(raw.get("ppl_enabled") or False),
                    ppl_level=int(raw.get("ppl_level") or 0),
                    lsass_pid=raw.get("lsass_pid"),
                )
        return HostFingerprint(
            target_ip=raw.get("target_ip", ""),
            products=products,
            defender_rtp=bool(raw.get("defender_rtp", True)),
            elapsed_s=float(raw.get("elapsed_s", 0.0)),
            error=raw.get("error"),
        )


__all__ = ["HostIntelligenceCache"]
