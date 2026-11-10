"""Centralized loot-cache helpers shared by WinRM, SMB, and MSSQL credential hunts.

All three transports fetch files from remote Windows hosts and run the same
phase-based analysis (CredSweeper, artifact analysis, etc.).  Refetching
hundreds or thousands of files when the remote filesystem has not changed is
expensive and unnecessary.

This service provides a transport-agnostic cache layer:

* ``read_loot_cache_metadata`` / ``write_loot_cache_metadata`` — JSON envelope
  stored alongside the loot directory.
* ``resolve_loot_cache_age_seconds`` — age calculation that uses
  ``os.path.getmtime()`` instead of the stored ``generated_at`` wall-clock
  timestamp.  This makes the age immune to clock adjustments that happen
  *during a session* (e.g. Kerberos ``KRB_AP_ERR_SKEW`` recovery that can
  jump the system clock by several minutes).  The stored timestamp is kept for
  human readability and audit trails only.
* ``decide_loot_cache_reuse`` — single UX decision point:
  - CTF workspace → auto-reuse if fresh, skip prompt.
  - Audit workspace → always prompt with default=False (environment can
    change between engagements; never silently reuse stale loot).
* ``make_cached_loot_fetcher`` — returns a no-op fetcher that reads existing
  local files instead of hitting the network.

# TODO: Unify with SMBRclonePhaseCacheService (content-addressed cache)
#
# The SMB rclone path already has a superior cache architecture: it is
# content-addressed (signature built from the phase candidate entry list),
# caches both raw loot files AND CredSweeper/artifact analysis results, and
# self-invalidates when remote content changes — no TTL or user prompt needed.
#
# WinRM and MSSQL use a time-based loot-only cache (this module), which is
# weaker: it does not cache analysis results and relies on TTL + user prompts
# instead of content signatures.
#
# The right fix is to extend ``WindowsSensitivePhaseExecutionService.execute_phase``
# with a ``phase_cache_dir`` parameter that builds the phase signature from
# ``selected_entries``, persists findings alongside the signature, and restores
# them without calling the fetcher or re-running CredSweeper when the signature
# matches.  That makes all three transports (WinRM, MSSQL, SMB rclone_direct)
# content-addressed, and SMBRclonePhaseCacheService becomes a thin wrapper.
#
# Defer until a dedicated PR with GOAD + Puppy + Active lab validation.
"""

from __future__ import annotations

from adscan_core.scan_policy import settings as policy_settings

import json
import os
import time
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Callable

from adscan_internal import print_info, print_info_debug
from adscan_internal.rich_output import mark_sensitive

if TYPE_CHECKING:
    from adscan_internal.services.windows_artifact_acquisition_service import (
        WindowsArtifactAcquisitionResult,
    )

# Loot (downloaded files) — age thresholds for the reuse prompt.
LOOT_CACHE_MAX_AGE_CTF: timedelta = timedelta(hours=4)
LOOT_CACHE_MAX_AGE_AUDIT: timedelta = timedelta(hours=12)

# Filesystem mapping (file-tree enumeration) — typically slower to regenerate
# than loot download; CTF boxes are static so a 30-minute mapping is still valid.
MAPPING_CACHE_MAX_AGE_CTF: timedelta = timedelta(minutes=30)
MAPPING_CACHE_MAX_AGE_AUDIT: timedelta = timedelta(hours=4)


def read_loot_cache_metadata(meta_path: str) -> dict[str, object] | None:
    """Read loot-cache metadata from disk; return None when absent or corrupt."""
    if not os.path.exists(meta_path):
        return None
    try:
        with open(meta_path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def write_loot_cache_metadata(
    meta_path: str,
    *,
    file_count: int,
    host: str,
    username: str,
    phase: str,
    transport: str = "winrm",
) -> None:
    """Persist loot-cache metadata so subsequent runs can detect and reuse it."""
    from datetime import datetime, timezone

    meta = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "file_count": file_count,
        "host": host,
        "username": username,
        "phase": phase,
        "transport": transport,
    }
    try:
        os.makedirs(os.path.dirname(meta_path), exist_ok=True)
        with open(meta_path, "w") as f:
            json.dump(meta, f)
    except Exception:
        pass


def resolve_loot_cache_age_seconds(meta_path: str) -> float | None:
    """Return the cache age in seconds using the file's mtime.

    Using ``os.path.getmtime()`` instead of the stored ``generated_at``
    wall-clock timestamp makes the age calculation immune to NTP / Kerberos
    clock-sync jumps that can happen during a session.  The ``generated_at``
    field in the JSON is kept for human readability only.
    """
    try:
        mtime = os.path.getmtime(meta_path)
        return max(0.0, time.time() - mtime)
    except OSError:
        return None


def make_cached_loot_fetcher(loot_dir: str) -> Callable[[], "WindowsArtifactAcquisitionResult"]:
    """Return a fetcher that skips the remote download and reads existing local files."""
    from adscan_internal.services.windows_artifact_acquisition_service import (
        WindowsArtifactAcquisitionResult,
    )

    def _fetch() -> WindowsArtifactAcquisitionResult:
        files: list[str] = []
        for root, _, names in os.walk(loot_dir):
            for name in names:
                files.append(os.path.join(root, name))
        return WindowsArtifactAcquisitionResult(
            downloaded_files=files,
            staged_file_count=len(files),
        )

    return _fetch


def decide_loot_cache_reuse(
    shell: Any,
    *,
    loot_dir: str,
    meta_path: str,
    phase_label: str,
    transport_label: str = "WinRM",
) -> bool:
    """Decide whether to reuse existing local loot instead of re-fetching.

    Decision logic:
    - No metadata or no files on disk → always fetch fresh (return False).
    - CTF workspace + cache within ``LOOT_CACHE_MAX_AGE_CTF`` →
      auto-reuse with a ``print_info`` message, no prompt.
    - CTF workspace + stale cache → prompt with default=True (still fresh
      enough to be useful, environment unlikely to have changed).
    - Audit workspace → always prompt with default=False (environment can
      change between runs; never silently reuse loot in a real engagement).

    Returns True when the caller should skip the remote fetch.
    """
    meta = read_loot_cache_metadata(meta_path)
    if not meta:
        return False

    cached_file_count = int(meta.get("file_count") or 0)
    if cached_file_count == 0:
        return False

    # Check that loot files are actually present (meta could be stale from a
    # partial write or manual deletion of the loot directory).
    if not os.path.isdir(loot_dir):
        return False

    age_seconds = resolve_loot_cache_age_seconds(meta_path)
    if age_seconds is None:
        return False

    age_hours = age_seconds / 3600.0
    if age_hours < 1.0:
        age_label = f"{int(age_seconds / 60)}m old"
    else:
        age_label = f"{age_hours:.1f}h old"

    # Labs are reset between runs, so their loot ages faster (genuinely
    # environment: the scan policy's).
    is_ctf = policy_settings.is_lab(shell)
    max_age = LOOT_CACHE_MAX_AGE_CTF if is_ctf else LOOT_CACHE_MAX_AGE_AUDIT
    cache_fresh = age_seconds <= max_age.total_seconds()

    marked_phase = mark_sensitive(phase_label, "text")
    marked_host = mark_sensitive(str(meta.get("host") or ""), "hostname")

    print_info(
        f"Previous {transport_label} loot found for {marked_phase}: "
        f"{cached_file_count} files, {age_label}."
    )
    print_info_debug(
        f"Loot cache check: transport={transport_label} "
        f"host={marked_host} phase={marked_phase} "
        f"file_count={cached_file_count} age_seconds={age_seconds:.0f} "
        f"cache_fresh={cache_fresh} lab={is_ctf}"
    )

    # Non-interactive (CI / pipe / auto): auto-reuse in CTF (stable env), skip in audit.
    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive(shell):
        if is_ctf:
            print_info(
                f"Non-interactive: reusing cached {transport_label} loot for {marked_phase}."
            )
            return True
        return False

    from rich.prompt import Confirm

    # Always prompt so the operator can force a refresh when a previous run was
    # incomplete or loot is known-stale.
    # CTF + fresh cache  → default Yes  (stable env, just press Enter)
    # CTF + stale cache  → default No   (old enough that a refresh is warranted)
    # Audit              → default No   (environment can change between engagements)
    default_reuse = is_ctf and cache_fresh
    prompt = (
        f"Re-use cached loot to skip re-fetch? "
        f"({cached_file_count} files, {age_label})"
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        return bool(confirmer(prompt, default=default_reuse))
    return Confirm.ask(prompt, default=default_reuse)


def decide_mapping_cache_reuse(
    shell: Any,
    *,
    manifest_path: str,
    entry_count: int,
    transport_label: str = "WinRM",
) -> bool:
    """Decide whether to reuse a cached filesystem mapping (file-tree enumeration).

    Same prompt/default logic as ``decide_loot_cache_reuse`` but for the
    mapping step.  Age is computed from ``os.path.getmtime(manifest_path)``
    so Kerberos clock-sync jumps during the session don't skew the result.

    Returns True when the caller should skip re-enumeration.
    """
    age_seconds = resolve_loot_cache_age_seconds(manifest_path)
    if age_seconds is None:
        return False

    is_ctf = policy_settings.is_lab(shell)
    max_age = MAPPING_CACHE_MAX_AGE_CTF if is_ctf else MAPPING_CACHE_MAX_AGE_AUDIT
    cache_fresh = age_seconds <= max_age.total_seconds()

    if age_seconds < 60:
        age_label = f"{int(age_seconds)}s old"
    elif age_seconds < 3600:
        age_label = f"{int(age_seconds / 60)}m old"
    else:
        age_label = f"{age_seconds / 3600:.1f}h old"

    print_info(
        f"Cached {transport_label} filesystem mapping found: "
        f"{entry_count} file entries, {age_label}."
    )
    print_info_debug(
        f"Mapping cache check: transport={transport_label} "
        f"entries={entry_count} age_seconds={age_seconds:.0f} "
        f"cache_fresh={cache_fresh} lab={is_ctf}"
    )

    # Non-interactive (CI / pipe / auto): auto-reuse in CTF, skip in audit.
    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive(shell):
        if is_ctf:
            print_info(
                f"Non-interactive: reusing cached {transport_label} mapping."
            )
            return True
        return False

    from rich.prompt import Confirm

    # Always prompt — operator may want to force re-enumeration even in CTF
    # (e.g. previous run was incomplete).
    # CTF + fresh → default Yes; CTF + stale or audit → default No.
    default_reuse = is_ctf and cache_fresh
    prompt = (
        f"Re-use cached filesystem mapping to skip re-enumeration? "
        f"({entry_count} entries, {age_label})"
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        return bool(confirmer(prompt, default=default_reuse))
    return Confirm.ask(prompt, default=default_reuse)


_T = None  # forward-compatible slot; TypeVar would require typing import


def try_use_mapping_cache(
    shell: Any,
    *,
    manifest_path: str,
    transport_label: str,
    loader: Callable[[], "tuple[int, Any] | None"],
) -> Any | None:
    """Try to load and reuse a cached filesystem mapping.

    This is the single entry point for all three transports (WinRM, SMB,
    MSSQL).  Each transport provides a ``loader`` callable that encapsulates
    its own load + compatibility-check logic and returns
    ``(entry_count, cached_data)`` when the cache is valid, or ``None`` when
    it is not (schema mismatch, empty, corrupt, incompatible metadata, …).

    The function then calls ``decide_mapping_cache_reuse`` to prompt/auto-
    select, and returns ``cached_data`` when the operator accepts reuse, or
    ``None`` when they decline or the cache is absent/invalid.

    Exceptions from ``loader`` are caught and logged as debug warnings so
    a corrupt cache never blocks a fresh enumeration.

    Usage::

        def _load() -> tuple[int, Any] | None:
            data = mapping_service.load_file_map(input_path=manifest_path)
            compatible, reason = check_compatible(data, expected_meta)
            if not compatible:
                return None
            entries = list(data.get("entries") or [])
            return len(entries), data

        cached = try_use_mapping_cache(
            shell,
            manifest_path=manifest_path,
            transport_label="WinRM",
            loader=_load,
        )
        if cached is not None:
            use(cached)
        else:
            fresh = generate()
            use(fresh)
    """
    if not os.path.exists(manifest_path):
        return None
    try:
        result = loader()
    except Exception as exc:
        print_info_debug(
            f"Mapping cache loader failed ({transport_label}); "
            f"will re-enumerate. error={type(exc).__name__}: {exc}"
        )
        return None

    if result is None:
        return None

    entry_count, cached_data = result
    if not decide_mapping_cache_reuse(
        shell,
        manifest_path=manifest_path,
        entry_count=entry_count,
        transport_label=transport_label,
    ):
        return None

    return cached_data


__all__ = [
    "LOOT_CACHE_MAX_AGE_AUDIT",
    "LOOT_CACHE_MAX_AGE_CTF",
    "MAPPING_CACHE_MAX_AGE_AUDIT",
    "MAPPING_CACHE_MAX_AGE_CTF",
    "decide_loot_cache_reuse",
    "decide_mapping_cache_reuse",
    "make_cached_loot_fetcher",
    "try_use_mapping_cache",
    "read_loot_cache_metadata",
    "resolve_loot_cache_age_seconds",
    "write_loot_cache_metadata",
]
