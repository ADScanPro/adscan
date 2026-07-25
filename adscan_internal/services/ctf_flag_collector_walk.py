"""Bounded SMB recursive walk for the CTF flag collector.

Wraps :meth:`aiosmb.commons.interfaces.directory.SMBDirectory.list_r`
with a filename filter so the walker emits only plausible flag
candidates. The actual byte-read of each candidate happens upstream —
this module never reads file contents, it only enumerates names.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from adscan_internal import print_info_debug, telemetry

from adscan_internal.services.ctf_flag_collector_catalog import (
    TOP_LEVEL_LIST_TIMEOUT_SECONDS,
    WALK_DEPTH,
    WALK_EXCLUDE_DIRS,
    WALK_MAX_ENTRIES,
    is_custom_top_level_dir,
    is_flag_candidate_name,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_core.rich_output import print_exception


@dataclass(slots=True)
class WalkOutcome:
    """Result of one walk root.

    Attributes:
        candidates: Share-relative paths matching the flag-candidate
            filter (e.g. ``\\C$\\inetpub\\wwwroot\\flag.txt``).
        files_scanned: Number of file entries observed (regardless of
            whether they matched the filter).
        dirs_traversed: Number of directories descended into.
        dirs_excluded: Number of directories skipped via the exclude list.
        hit_max_entries: ``True`` if the walk was capped by ``maxentries``.
        error: First fatal error encountered, if any.
    """

    candidates: list[str]
    files_scanned: int
    dirs_traversed: int
    dirs_excluded: int
    entries_errored: int  # entries where list_r returned err (ACCESS_DENIED etc.)
    hit_max_entries: bool
    error: str | None


def _build_smb_directory(connection, root_path: str):
    """Return an ``SMBDirectory`` for ``root_path`` under the host.

    ``root_path`` is share-relative (``\\C$\\Users\\``). aiosmb's
    ``from_remotepath`` resolves it against the connection's host.
    """
    from aiosmb.commons.interfaces.directory import SMBDirectory

    return SMBDirectory.from_remotepath(connection, root_path)


async def walk_root(
    connection,
    *,
    root_path: str,
    depth: int = WALK_DEPTH,
    max_entries: int = WALK_MAX_ENTRIES,
    exclude_dirs: tuple[str, ...] = WALK_EXCLUDE_DIRS,
) -> WalkOutcome:
    """Walk ``root_path`` and return flag-candidate paths.

    Args:
        connection: Open ``SMBConnection`` instance.
        root_path: Share-relative starting directory.
        depth: Maximum recursion depth.
        max_entries: Hard cap on total entries enumerated.
        exclude_dirs: Directory basenames to skip.

    Returns:
        :class:`WalkOutcome` with candidate paths and walk statistics.
    """
    candidates: list[str] = []
    files_scanned = 0
    dirs_traversed = 0
    dirs_excluded = 0
    entries_errored = 0  # entries where list_r returned err — helps diagnose silent walk failures
    hit_max = False
    err_text: str | None = None

    excludes_lower = [d.lower() for d in exclude_dirs]

    async def _filter(otype: str, obj) -> bool:
        nonlocal dirs_excluded
        # Filter is consulted before descending into a dir. Skip system
        # directories by basename (case-insensitive). list_r already
        # handles the configured ``exclude_dir`` list, but its match is
        # case-sensitive — we widen it here for robustness.
        if otype == "dir":
            name = (getattr(obj, "name", "") or "").lower()
            if name in excludes_lower:
                dirs_excluded += 1
                return False
        return True

    try:
        directory = _build_smb_directory(connection, root_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return WalkOutcome([], 0, 0, 0, 0, False, f"directory init failed: {exc}")

    try:
        async for obj, otype, err in directory.list_r(
            connection,
            depth=depth,
            maxentries=max_entries,
            exclude_dir=list(exclude_dirs),
            filter_cb=_filter,
        ):
            if otype == "maxed":
                hit_max = True
                break
            if err is not None:
                # Per-entry errors (ACCESS_DENIED on a subdir, etc.) are
                # benign — they just mean the walker can't see that
                # branch. Don't surface them as fatal.
                entries_errored += 1
                continue
            if otype == "dir":
                dirs_traversed += 1
                continue
            if otype == "file":
                files_scanned += 1
                name = getattr(obj, "name", "") or ""
                size = int(getattr(obj, "size", 0) or 0)
                if is_flag_candidate_name(name, size=size):
                    fullpath = getattr(obj, "fullpath", "") or ""
                    if fullpath:
                        # ``fullpath`` is share-relative
                        # (``Users\\X\\Desktop\\foo.txt``). Re-prefix
                        # to the canonical ``\\C$\\...`` form used by
                        # the rest of the collector.
                        share_path = "\\C$\\" + fullpath.lstrip("\\")
                        candidates.append(share_path)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        err_text = f"walk failed: {exc}"

    # If all entries errored (entries_errored > 0 but files=dirs=0), it means the
    # walk's SMB connection listed nothing usable — log at warning level so
    # operators can see the walk was not silently skipped but had access issues.
    if entries_errored > 0 and files_scanned == 0 and dirs_traversed == 0:
        print_info_debug(
            f"[ctf-flags] walk root={root_path} SILENT FAILURE: "
            f"{entries_errored} entries returned errors, 0 files/dirs accessible. "
            "Walk SMB connection may have had auth or timing issues — "
            "the ps_search fallback will cover this."
        )
    print_info_debug(
        f"[ctf-flags] walk root={root_path} files={files_scanned} "
        f"dirs={dirs_traversed} excluded={dirs_excluded} "
        f"errored={entries_errored} candidates={len(candidates)} maxed={hit_max}"
    )

    return WalkOutcome(
        candidates=candidates,
        files_scanned=files_scanned,
        dirs_traversed=dirs_traversed,
        dirs_excluded=dirs_excluded,
        entries_errored=entries_errored,
        hit_max_entries=hit_max,
        error=err_text,
    )


async def enumerate_top_level_dirs(
    connection,
    *,
    root_path: str = r"\C$\\",
    list_timeout_seconds: float = TOP_LEVEL_LIST_TIMEOUT_SECONDS,
) -> tuple[list[str], str | None]:
    """List the CUSTOM top-level directories under ``\\C$\\``.

    Runs a single, cheap, non-recursive directory enumeration of the C:
    drive root via :meth:`SMBDirectory.list`, then filters to the custom
    operator/box-author directories (excluding Windows system dirs and the
    dirs already covered by dedicated walk roots). This is the cheap
    pre-step that replaces the removed unbounded ``\\C$\\`` recursive walk.

    Args:
        connection: Open ``SMBConnection`` instance.
        root_path: Share-relative drive root to enumerate (default ``\\C$\\``).
        list_timeout_seconds: Hard timeout for the single directory listing.

    Returns:
        ``(custom_dir_names, error_or_None)``. ``custom_dir_names`` are bare
        top-level basenames (e.g. ``["share", "backup"]``), never paths.
    """
    try:
        directory = _build_smb_directory(connection, root_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return [], f"top-level directory init failed: {exc}"

    try:
        ok, err = await asyncio.wait_for(
            directory.list(connection),
            timeout=list_timeout_seconds,
        )
    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError:
        print_info_debug(
            f"[ctf-flags] top-level list root={root_path} OUTCOME=timeout "
            f"(exceeded {list_timeout_seconds:.0f}s)"
        )
        return [], f"top-level list timed out after {list_timeout_seconds:.0f}s"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[ctf-flags] top-level list root={root_path} OUTCOME=error err={exc}"
        )
        return [], f"top-level list failed: {exc}"

    if err is not None:
        print_info_debug(
            f"[ctf-flags] top-level list root={root_path} OUTCOME=error err={err}"
        )
        return [], f"top-level list returned error: {err}"
    if ok is False:
        print_info_debug(
            f"[ctf-flags] top-level list root={root_path} OUTCOME=error "
            "(listing reported failure)"
        )
        return [], "top-level list reported failure"

    subdirs = getattr(directory, "subdirs", {}) or {}
    all_names = list(subdirs.keys())
    custom = [name for name in all_names if is_custom_top_level_dir(name)]

    masked = ", ".join(mark_sensitive(n, "path") for n in custom) or "<none>"
    print_info_debug(
        f"[ctf-flags] top-level list root={root_path} OUTCOME=ok "
        f"total_dirs={len(all_names)} custom_dirs={len(custom)}: {masked}"
    )
    return custom, None


__all__ = ["WalkOutcome", "walk_root", "enumerate_top_level_dirs"]
