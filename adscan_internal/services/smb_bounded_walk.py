r"""Bounded, targeted SMB share walk — one reusable primitive over aiosmb ``list_r``.

Every native SMB walk in ADscan (GPP harvest, CTF flag hunt, share-tree mapping)
drives the vendor async generator ``SMBDirectory.list_r`` and then hand-rolls the
SAME missing layer on top of it: a per-root time budget that keeps partial results,
a total-file cap, and iteration over several roots on ONE connection. ``list_r``
gives depth/entry caps, ``exclude_dir`` and a ``filter_cb`` but **no time bound and
no per-root semantics** — so each caller reinvents them, and the GPP harvester got
it wrong (one global ``wait_for`` around every share that cancels the whole walk on
timeout, losing everything with ``shares=[]`` instead of a partial result).

This module extracts that layer once, modeled on the most complete existing
implementation (``_native_walk_host_share_tree`` in ``cli/smb.py``):

* **per-root time budget** — each root is walked under its own ``wait_for`` so one
  slow/pathological root cannot starve the others, and a timeout keeps whatever the
  ``on_file`` callback already applied (true partial results);
* **total-file cap** — bounds blast radius across all roots;
* **targeted roots** — a root is any UNC, ``\\host\SHARE`` OR a deeper subpath like
  ``\\host\SYSVOL\<domain>\Policies``; ``from_uncpath`` + ``list_r`` navigate to the
  subdir natively, so a caller can walk exactly the subtree it needs instead of the
  whole share (the difference between O(#GPOs) and O(entire SYSVOL)).

The caller supplies ``on_file`` (sync or async), invoked once per file entry with the
vendor ``SMBFile``; it decides what to extract (parse XML, read content, record
metadata). This module owns only the bounding. Subprocess/mount-based searches
(rclone, manspider, CredSweeper-over-CIFS) are a different pattern and do NOT belong
here — this is strictly an aiosmb ``list_r`` wrapper.

Pure async orchestration: it imports only the vendor SMB directory interface and
stdlib. Safe to consume from any service that already holds a logged-in
``aiosmb.SMBConnection``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Sequence

#: An ``on_file`` callback: receives the vendor ``SMBFile`` for one file entry and
#: may return ``None`` (sync) or an awaitable (async). Exceptions it raises are
#: caught per-file so one bad file never aborts the walk.
OnFile = Callable[[Any], "Awaitable[None] | None"]


@dataclass
class ShareWalkOutcome:
    """What a :func:`bounded_share_walk` run observed.

    ``partial`` is ``True`` when any root hit its time budget (or the overall one),
    so the caller can report an honest coverage gap instead of a silent truncation.
    """

    files_seen: int = 0
    roots_walked: list[str] = field(default_factory=list)
    roots_timed_out: list[str] = field(default_factory=list)
    max_files_reached: bool = False
    last_error: str = ""

    @property
    def partial(self) -> bool:
        """True when a time budget cut a root short (results are incomplete)."""

        return bool(self.roots_timed_out)


async def bounded_share_walk(
    connection: Any,
    *,
    roots: Sequence[str],
    on_file: OnFile,
    depth: int,
    max_files: int,
    per_root_timeout: float,
    overall_timeout: float | None = None,
    exclude_dir: Sequence[str] = (),
    filter_cb: Any = None,
) -> ShareWalkOutcome:
    r"""Walk ``roots`` on one SMB ``connection`` with per-root time budgets.

    Args:
        connection: A logged-in ``aiosmb.SMBConnection`` (the caller owns its
            lifecycle). All roots are walked sequentially over this one connection
            — never concurrently (a single ``SMBConnection`` is not concurrency-safe
            across pipes; see the connection docstring). Open several connections
            for genuine parallelism.
        roots: Full UNC roots to walk. Each is ``\\host\SHARE`` or a deeper subpath
            (``\\host\SYSVOL\<domain>\Policies``); the subpath is navigated natively.
        on_file: Called once per file entry with the vendor ``SMBFile``. Sync or
            async. A file it raises on is skipped (recorded in ``last_error``), never
            fatal — so one unreadable file cannot abort the walk.
        depth: Max recursion depth below each root (passed to ``list_r``). Count it
            from the root: a file N directories deep needs ``depth >= N``.
        max_files: Hard cap on file entries across ALL roots. Bounds blast radius on
            a misconfigured/huge subtree.
        per_root_timeout: Seconds budget for EACH root. A root that exceeds it is
            abandoned with its partial ``on_file`` side effects kept, and the walk
            moves to the next root. Size it for real-network latency, not a lab.
        overall_timeout: Optional cap on the whole walk across all roots. ``None``
            relies solely on the per-root budgets (the usual choice for a targeted
            walk, which is already bounded by design).
        exclude_dir: Directory names to skip (passed to ``list_r``).
        filter_cb: Optional ``list_r`` filter callback (``('dir'|'file', obj)``).

    Returns:
        A :class:`ShareWalkOutcome`. Side effects (what was found) flow through
        ``on_file``; this return value reports coverage — how many files were seen,
        which roots completed, and which were cut short by a budget.
    """

    from aiosmb.commons.interfaces.directory import SMBDirectory

    outcome = ShareWalkOutcome()
    exclude = list(exclude_dir)

    async def _walk_one(root_unc: str) -> None:
        try:
            root_dir = SMBDirectory.from_uncpath(root_unc)
        except Exception as exc:  # noqa: BLE001
            outcome.last_error = f"{root_unc}: from_uncpath {type(exc).__name__}"
            return
        walked_any = False
        async for path, otype, err in root_dir.list_r(
            connection, depth=depth, exclude_dir=exclude, filter_cb=filter_cb
        ):
            if outcome.files_seen >= max_files:
                outcome.max_files_reached = True
                return
            if err is not None:
                outcome.last_error = f"{root_unc}: {err}"
                continue
            walked_any = True
            if otype != "file":
                continue
            outcome.files_seen += 1
            try:
                result = on_file(path)
                if asyncio.iscoroutine(result):
                    await result
            except asyncio.CancelledError:
                # A per-root timeout cancels the walk here — propagate so the
                # partial results already applied by on_file are kept.
                raise
            except Exception as exc:  # noqa: BLE001
                outcome.last_error = f"{root_unc}: on_file {type(exc).__name__}"
                continue
        if walked_any and root_unc not in outcome.roots_walked:
            outcome.roots_walked.append(root_unc)

    async def _drive() -> None:
        for root_unc in roots:
            if outcome.files_seen >= max_files:
                outcome.max_files_reached = True
                break
            try:
                await asyncio.wait_for(_walk_one(root_unc), timeout=per_root_timeout)
            except asyncio.TimeoutError:
                # The root exceeded its budget; on_file side effects so far are kept.
                if root_unc not in outcome.roots_timed_out:
                    outcome.roots_timed_out.append(root_unc)

    if overall_timeout is not None:
        try:
            await asyncio.wait_for(_drive(), timeout=overall_timeout)
        except asyncio.TimeoutError:
            if "<overall>" not in outcome.roots_timed_out:
                outcome.roots_timed_out.append("<overall>")
    else:
        await _drive()

    return outcome


__all__ = ["ShareWalkOutcome", "bounded_share_walk", "OnFile"]
