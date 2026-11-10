"""One patch-level read per host per run, shared by every patch-level CVE check.

Several CVE checks cannot be confirmed by a network probe and are graded from
the host's patch level instead (``CurrentBuildNumber`` and ``UBR`` read over
Remote Registry, :mod:`.checks._os_patch_level`): Drop the MIC 2
(CVE-2019-1166) and PrintNightmare (CVE-2021-34527) today. Before this module
each check opened its own session and read the same two values, and each did
so with the scan credential, which most hosts refuse.

This module owns two things:

* **The cache.** :class:`HostPatchLevelCache` keeps the first successful read of
  each host for the run, keyed alias-aware (IP and FQDN of one host are one
  entry). Every check asks the cache first, so the first check to reach a host
  reads it and the others reuse the value. A failed read is remembered per
  ``(access, principal)`` so the same failing credential is not tried twice,
  while a different (administrator) credential still gets its attempt. The
  cache is also written to the host record in the workspace,
  ``domains/<domain>/inventory/host_patch_level.json``, for the operator and
  for evidence. It is NOT read back by a later run: a host patched between two
  runs must be read again.
* **The credential choice.** :meth:`HostPatchLevelCache.resolve_access` asks the
  resolver installed by the caller (``host_admin_access``) for an administrator
  of the host: Domain Admin first, then that host's own local administrator
  material. An administrative read is preferred because it is the one that
  succeeds; the scan credential stays the fallback.

Every read carries the access that produced it (``OSVersionRead.access``), so a
verdict can say "inferred from the patch level, read with administrative
access". A host that no credential could read stays "not assessed" with its
reason, never "not vulnerable".
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.checks._os_patch_level import (
    ACCESS_ADMINISTRATIVE,
    ACCESS_STANDARD,
    READ_FAILED,
    OSVersionRead,
    read_os_version_with_config,
)

#: The host record file, under ``domains/<domain>/inventory/``.
PATCH_LEVEL_RECORD_FILENAME = "host_patch_level.json"
_RECORD_VERSION = 1


@dataclass(frozen=True)
class HostAccess:
    """An administrator credential resolved for one host.

    ``config`` is the ``SMBConfig`` to open the session with. ``source`` says
    where the proof of administration came from (``domain_admin``,
    ``local_admin_verified`` or ``local_account``); ``principal`` is the account
    name, for the attempt memo and debug logs only.
    """

    config: Any
    principal: str
    source: str
    access: str = ACCESS_ADMINISTRATIVE


AccessResolver = Callable[[str, "str | None"], "HostAccess | None"]
Reader = Callable[[], Awaitable[OSVersionRead]]


def _norm_alias(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


class HostPatchLevelCache:
    """Per-run, alias-aware cache of host patch levels (see the module docstring)."""

    def __init__(
        self,
        *,
        record_path: Path | None = None,
        access_resolver: AccessResolver | None = None,
    ) -> None:
        self._record_path = record_path
        self._access_resolver = access_resolver
        self._alias_to_key: dict[str, str] = {}
        self._aliases: dict[str, set[str]] = {}
        self._ok: dict[str, OSVersionRead] = {}
        self._last: dict[str, OSVersionRead] = {}
        self._attempts: dict[str, dict[tuple[str, str], OSVersionRead]] = {}
        self._read_at: dict[str, str] = {}
        self._access_memo: dict[str, HostAccess | None] = {}
        self._locks: dict[tuple[int, str], asyncio.Lock] = {}
        self._dirty = False

    # ── identity ────────────────────────────────────────────────────────────

    def _key(self, hosts: tuple[Any, ...]) -> str:
        """Return the canonical key of the host named by any of ``hosts``."""
        aliases = [a for a in (_norm_alias(h) for h in hosts) if a]
        if not aliases:
            return ""
        key = next((self._alias_to_key[a] for a in aliases if a in self._alias_to_key), aliases[0])
        bucket = self._aliases.setdefault(key, set())
        for alias in aliases:
            other = self._alias_to_key.get(alias)
            if other is not None and other != key:
                # Two entries turned out to be one host: fold the other into key.
                self._merge_keys(into=key, other=other)
            self._alias_to_key[alias] = key
            bucket.add(alias)
        return key

    def _merge_keys(self, *, into: str, other: str) -> None:
        for alias in self._aliases.pop(other, set()):
            self._alias_to_key[alias] = into
            self._aliases.setdefault(into, set()).add(alias)
        if other in self._ok and into not in self._ok:
            self._ok[into] = self._ok[other]
            self._read_at[into] = self._read_at.get(other, "")
        self._ok.pop(other, None)
        other_last = self._last.pop(other, None)
        if other_last is not None and into not in self._last:
            self._last[into] = other_last
        self._attempts.setdefault(into, {}).update(self._attempts.pop(other, {}))

    def _lock(self, key: str) -> asyncio.Lock:
        # Locks are per event loop: the CVE phase and the post-collection re-run
        # run on different loops, and an asyncio.Lock must not cross loops.
        loop_id = id(asyncio.get_running_loop())
        return self._locks.setdefault((loop_id, key), asyncio.Lock())

    # ── reads ───────────────────────────────────────────────────────────────

    def cached(self, *hosts: Any) -> OSVersionRead | None:
        """The successful read of this host in this run, or ``None``."""
        key = self._key(hosts)
        return self._ok.get(key) if key else None

    def record(self, *hosts: Any, read: OSVersionRead) -> None:
        """Store a read another component made (write-through). Never raises."""
        key = self._key(hosts)
        if not key:
            return
        self._store(key, read)

    def _store(self, key: str, read: OSVersionRead) -> None:
        self._last[key] = read
        if read.build is not None and key not in self._ok:
            self._ok[key] = read
            self._read_at[key] = datetime.now(timezone.utc).isoformat()
        self._dirty = True

    async def get_or_read(
        self,
        *hosts: Any,
        access: str,
        principal: str,
        reader: Reader,
    ) -> OSVersionRead:
        """Return the host's cached patch level, reading it once when absent.

        A successful read in this run is returned whatever credential made it.
        Otherwise ``reader`` runs once per ``(access, principal)``: a credential
        that already failed on this host is not tried again in the run.
        """
        key = self._key(hosts)
        if not key:
            return await self._call(reader, access)
        async with self._lock(key):
            ok = self._ok.get(key)
            if ok is not None:
                return ok
            attempt_key = (access, str(principal or "").strip().lower())
            previous = self._attempts.get(key, {}).get(attempt_key)
            if previous is not None:
                return previous
            read = await self._call(reader, access)
            self._attempts.setdefault(key, {})[attempt_key] = read
            self._store(key, read)
            return read

    @staticmethod
    async def _call(reader: Reader, access: str) -> OSVersionRead:
        try:
            read = await reader()
        except Exception as exc:  # noqa: BLE001 - one host never breaks the scan
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            read = OSVersionRead(None, None, READ_FAILED, error=str(exc))
        return replace(read, access=access)

    # ── access ──────────────────────────────────────────────────────────────

    def set_access_resolver(self, resolver: AccessResolver | None) -> None:
        """Install the administrator-credential resolver and forget its answers."""
        self._access_resolver = resolver
        self._access_memo.clear()

    def reset_access(self) -> None:
        """Forget resolved access, so credentials gained since are considered."""
        self._access_memo.clear()

    async def resolve_access(self, host: str, target_hostname: str | None = None) -> HostAccess | None:
        """Return an administrator credential for the host, memoized per host."""
        if self._access_resolver is None:
            return None
        key = self._key((host, target_hostname))
        if key in self._access_memo:
            return self._access_memo[key]
        try:
            from adscan_internal.services.async_bridge import run_sync_off_loop  # noqa: PLC0415

            access = run_sync_off_loop(self._access_resolver, host, target_hostname)
        except Exception as exc:  # noqa: BLE001 - no access means the standard read
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            access = None
        self._access_memo[key] = access
        return access

    # ── host record ─────────────────────────────────────────────────────────

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """The run's per-host records (successful or last failed read)."""
        out: dict[str, dict[str, Any]] = {}
        for key, last in self._last.items():
            read = self._ok.get(key, last)
            out[key] = {
                "aliases": sorted(self._aliases.get(key, {key})),
                "build": read.build,
                "ubr": read.ubr,
                "access": read.access,
                "reason": "" if read.build is not None else (read.reason or READ_FAILED),
                "read_at": self._read_at.get(key, ""),
            }
        return out

    def flush(self) -> None:
        """Merge this run's records into the workspace host record. Never raises."""
        if not self._dirty or self._record_path is None:
            return
        try:
            existing: dict[str, Any] = {}
            if self._record_path.is_file():
                loaded = json.loads(self._record_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("hosts"), dict):
                    existing = loaded["hosts"]
            current = self.snapshot()
            for key, record in current.items():
                # Drop stale entries recorded under any alias of this host.
                for alias in record["aliases"]:
                    if alias != key:
                        existing.pop(alias, None)
                previous = existing.get(key)
                # Never let a failed read of this run hide a value an earlier
                # run recorded: keep the earlier value, note this run's reason.
                if record["build"] is None and isinstance(previous, dict) and previous.get("build") is not None:
                    previous = dict(previous)
                    previous["last_attempt_reason"] = record["reason"]
                    existing[key] = previous
                    continue
                existing[key] = record
            self._record_path.parent.mkdir(parents=True, exist_ok=True)
            self._record_path.write_text(
                json.dumps({"version": _RECORD_VERSION, "hosts": existing}, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            self._dirty = False
        except Exception as exc:  # noqa: BLE001 - the record is informative only
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


async def read_patch_level(
    cache: HostPatchLevelCache,
    *,
    host: str,
    target_hostname: str | None,
    standard_principal: str,
    standard_reader: Reader | None,
    admin_reader: Callable[[Any], Awaitable[OSVersionRead]] | None = None,
) -> OSVersionRead:
    """The host's patch level: cached, else an administrator read, else the scan credential's.

    The administrator read is tried first because it is the one that succeeds
    on a default host. If it fails (a local administrator whose remote token is
    filtered, a stale password), the scan credential still gets its own attempt;
    when both fail, the administrator's failure is returned (it carries the
    more useful reason).
    """
    cached = cache.cached(host, target_hostname)
    if cached is not None:
        return cached
    admin_read = admin_reader or read_os_version_with_config
    admin_failure: OSVersionRead | None = None
    access = await cache.resolve_access(host, target_hostname)
    if access is not None:
        read = await cache.get_or_read(
            host,
            target_hostname,
            access=ACCESS_ADMINISTRATIVE,
            principal=access.principal,
            reader=lambda: admin_read(access.config),
        )
        if read.build is not None:
            return read
        admin_failure = read
        print_info_debug(
            f"[patch-level] administrative read of {mark_sensitive(host, 'host')} "
            f"did not return the build ({read.reason or read.error or 'no value'})"
        )
    if standard_reader is not None:
        read = await cache.get_or_read(
            host,
            target_hostname,
            access=ACCESS_STANDARD,
            principal=standard_principal,
            reader=standard_reader,
        )
        if read.build is not None or admin_failure is None:
            return read
    return admin_failure or OSVersionRead(None, None, READ_FAILED, error="no credential to read the patch level")


def get_host_patch_level_cache(shell: Any, domain: str | None) -> HostPatchLevelCache:
    """Return the run's cache for ``domain``, created on first use.

    Lives on the shell (one run = one process), so the CVE phase and the
    post-collection re-run of the same run share it.
    """
    caches = getattr(shell, "_host_patch_level_caches", None)
    if not isinstance(caches, dict):
        caches = {}
        try:
            shell._host_patch_level_caches = caches  # noqa: SLF001
        except Exception:  # noqa: BLE001 - a read-only shell still gets a cache
            pass
    key = _norm_alias(domain)
    cache = caches.get(key)
    if cache is None:
        cache = HostPatchLevelCache(record_path=_record_path(shell, domain))
        caches[key] = cache
    return cache


def _record_path(shell: Any, domain: str | None) -> Path | None:
    if not domain:
        return None
    try:
        from adscan_internal.workspaces.computers import domain_subpath  # noqa: PLC0415

        workspace = (
            shell._get_workspace_cwd()  # noqa: SLF001
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", "")
        ) or ""
        if not workspace:
            return None
        domains_dir = getattr(shell, "domains_dir", "domains") or "domains"
        return Path(
            domain_subpath(str(workspace), str(domains_dir), str(domain), "inventory", PATCH_LEVEL_RECORD_FILENAME)
        )
    except Exception as exc:  # noqa: BLE001 - no record file, cache still works
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def record_host_patch_level(
    shell: Any,
    *,
    domain: str | None,
    hosts: tuple[Any, ...],
    build: int | None,
    ubr: int | None,
    access: str,
) -> None:
    """Write-through for a component that read the patch level itself (CA probe)."""
    if shell is None or build is None:
        return
    try:
        cache = get_host_patch_level_cache(shell, domain)
        cache.record(*hosts, read=OSVersionRead(build, ubr, access=access))
        cache.flush()
    except Exception as exc:  # noqa: BLE001 - write-through is best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = [
    "AccessResolver",
    "HostAccess",
    "HostPatchLevelCache",
    "PATCH_LEVEL_RECORD_FILENAME",
    "get_host_patch_level_cache",
    "read_patch_level",
    "record_host_patch_level",
]
