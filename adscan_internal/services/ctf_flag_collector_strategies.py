"""Three independent flag-discovery strategies.

Each strategy opens its own ``SMBMachine`` session — three concurrent
reads on a single shared session corrupted aiosmb's state on Forest, so
the safer model is one connection per strategy. Three connections to the
same host run fine in parallel.

Public functions:

* :func:`probe_conventional` — Desktop standard locations, the fast path.
* :func:`probe_alternative` — Closed catalog of known non-Desktop paths.
* :func:`smb_walk_bounded` — Recursive walk with filename filter.
* :func:`powershell_search` — PowerShell recursive search (Strategy 4 fallback).

Each returns a :class:`StrategyOutcome` carrying hits, probe errors and
strategy-specific stats. The orchestrator in
:mod:`ctf_flag_collector` reduces the outcomes into a single
:class:`FlagCollectionResult`.

# TODO: Rethink strategy execution order
#
# Current order: conventional + alternative + smb_walk (parallel, always) →
# powershell_search (sequential, only if flags missing).
#
# The smb_walk runs even when exec (WinRM/atexec) is available and DA hash
# is in hand — in practice it returns 0 candidates on most boxes (e.g. Puppy:
# files=0 dirs=0) adding ~25s of latency for nothing.
#
# Better order when exec is available:
#   1. conventional + alternative (parallel, SMB byte-read only, ~5s)
#   2. powershell_search (covers all of C:\\Users\\ + C:\\ fallback, ~5-10s)
#   3. smb_walk only as pure-SMB fallback when powershell_search auth-fails
#
# Blocked on: need GOAD + Forest + Active lab coverage to ensure no regressions
# before touching the orchestrator.  Do not change strategy ordering without
# running all three lab profiles.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
from dataclasses import dataclass, field
from datetime import datetime, timezone

from adscan_internal import print_info_debug, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.ctf_flag_collector_catalog import (
    TOP_LEVEL_MAX_DIRS,
    TOP_LEVEL_PER_DIR_TIMEOUT_SECONDS,
    TOP_LEVEL_WALK_DEPTH,
    TOP_LEVEL_WALK_MAX_ENTRIES,
    WALK_ROOTS,
    WALK_TIMEOUT_SECONDS,
    build_alternative_candidates,
)
from adscan_internal.services.ctf_flag_collector_walk import (
    WalkOutcome,
    enumerate_top_level_dirs,
    walk_root,
)
from adscan_internal.services.smb_transport import (
    SMBAccessDeniedError,
    SMBAuthError,
    SMBConfig,
    SMBTransportError,
    smb_machine_with_fallback,
)
from adscan_core.rich_output import print_exception


@dataclass(slots=True)
class StrategyOutcome:
    """Aggregate output of one strategy run."""

    hits: list = field(default_factory=list)        # list[FlagHit]
    probe_errors: list = field(default_factory=list)  # list[FlagProbeError]
    errors: list[str] = field(default_factory=list)
    walk_stats: dict | None = None  # only populated by smb_walk_bounded
    aiosmb_stderr_lines: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Strategy 1 — Conventional Desktop paths
# ---------------------------------------------------------------------------


async def probe_conventional(
    *,
    config: SMBConfig,
    candidates: list[tuple[str, str, str]],  # (path, kind, owner)
    host: str,
    path_timeout_seconds: float,
    total_budget_seconds: float = 24.0,
) -> StrategyOutcome:
    """Probe the conventional ``\\Users\\<owner>\\Desktop\\*.txt`` paths.

    Runs sequentially within one SMB session — this is the proven pattern
    that survived the Forest flapping incident. ``total_budget_seconds``
    bounds the whole strategy (connect + probes + reconnects) so a single
    dead path cannot starve the reconnect re-probe of the Desktop paths.
    """
    # Imports kept local to avoid circular imports with the main module.
    from adscan_internal.services.ctf_flag_collector import (
        FlagDiscoveryStrategy,
        _smb_byte_read_strategy,
    )

    out = StrategyOutcome()
    try:
        hits, _denied, probe_errors, errors = await _smb_byte_read_strategy(
            config=config,
            candidates=candidates,
            path_timeout_seconds=path_timeout_seconds,
            host=host,
            total_budget_seconds=total_budget_seconds,
            discovered_via=FlagDiscoveryStrategy.CONVENTIONAL,
        )
        out.hits = hits
        out.probe_errors = probe_errors
        out.errors = errors
    except SMBAuthError as exc:
        out.errors.append(f"smb auth failed: {exc}")
    except (SMBAccessDeniedError, SMBTransportError) as exc:
        out.errors.append(f"smb connect failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        out.errors.append(f"conventional strategy: {exc}")
    return out


# ---------------------------------------------------------------------------
# Strategy 2 — Alternative known paths
# ---------------------------------------------------------------------------


async def probe_alternative(
    *,
    config: SMBConfig,
    users: list[str],
    host: str,
    path_timeout_seconds: float,
    total_budget_seconds: float = 24.0,
) -> StrategyOutcome:
    """Probe the alternative-paths catalog (web roots, ProgramData, etc.).

    ``total_budget_seconds`` bounds the whole strategy (see
    :func:`probe_conventional`).
    """
    from adscan_internal.services.ctf_flag_collector import (
        FlagDiscoveryStrategy,
        _smb_byte_read_strategy,
    )

    out = StrategyOutcome()
    raw = build_alternative_candidates(users)
    # Adapt to the (path, kind, owner-or-empty) shape used by the byte-read
    # strategy. owner=None becomes "" so downstream string operations stay safe.
    candidates = [(p, k, owner or "") for (p, k, owner) in raw]

    try:
        hits, _denied, probe_errors, errors = await _smb_byte_read_strategy(
            config=config,
            candidates=candidates,
            path_timeout_seconds=path_timeout_seconds,
            host=host,
            total_budget_seconds=total_budget_seconds,
            discovered_via=FlagDiscoveryStrategy.ALTERNATIVE,
        )
        out.hits = hits
        out.probe_errors = probe_errors
        out.errors = errors
    except SMBAuthError as exc:
        out.errors.append(f"smb auth failed: {exc}")
    except (SMBAccessDeniedError, SMBTransportError) as exc:
        out.errors.append(f"smb connect failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        out.errors.append(f"alternative strategy: {exc}")
    return out


# ---------------------------------------------------------------------------
# Strategy 3 — Bounded SMB walk
# ---------------------------------------------------------------------------


async def _walk_root_logged(
    conn,
    *,
    root_path: str,
    per_root_timeout: float,
    depth: int | None = None,
    max_entries: int | None = None,
) -> WalkOutcome:
    """Run :func:`walk_root` under a per-root timeout, ALWAYS logging outcome.

    The earlier dispatch let a root that raised, timed out, or was cancelled
    produce no diagnostic line at all (this is exactly how the live ``\\C$\\``
    and ``\\C$\\Users\\`` walks vanished from the log). This wrapper guarantees
    a single ``walk root=<root> OUTCOME=<ok|timeout|error|cancelled>`` line is
    emitted for every root, no matter how it terminates, and converts any
    terminal condition into a :class:`WalkOutcome` (never re-raises non-cancel
    errors) so the dispatcher can keep aggregating the other roots.

    Cancellation is re-raised (cooperative shutdown) but logged first.
    """
    kwargs: dict = {"root_path": root_path}
    if depth is not None:
        kwargs["depth"] = depth
    if max_entries is not None:
        kwargs["max_entries"] = max_entries

    try:
        res = await asyncio.wait_for(
            walk_root(conn, **kwargs),
            timeout=per_root_timeout,
        )
        # walk_root already emits its own detailed line; add a normalised
        # OUTCOME marker so every root is greppable the same way.
        print_info_debug(
            f"[ctf-flags] walk root={root_path} OUTCOME="
            f"{'error' if res.error else 'ok'} files={res.files_scanned} "
            f"dirs={res.dirs_traversed} errored={res.entries_errored} "
            f"candidates={len(res.candidates)}"
        )
        return res
    except asyncio.CancelledError:
        print_info_debug(
            f"[ctf-flags] walk root={root_path} OUTCOME=cancelled "
            "files=0 dirs=0 errored=0 candidates=0"
        )
        raise
    except asyncio.TimeoutError:
        print_info_debug(
            f"[ctf-flags] walk root={root_path} OUTCOME=timeout "
            f"(exceeded {per_root_timeout:.0f}s) files=0 dirs=0 errored=0 candidates=0"
        )
        return WalkOutcome([], 0, 0, 0, 0, False, f"walk timed out after {per_root_timeout:.0f}s")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[ctf-flags] walk root={root_path} OUTCOME=error "
            f"files=0 dirs=0 errored=0 candidates=0 err={exc}"
        )
        return WalkOutcome([], 0, 0, 0, 0, False, f"walk error: {exc}")


async def _discover_top_level_walks(
    conn,
    *,
    per_dir_timeout: float,
) -> list[tuple[str, WalkOutcome]]:
    """Shallow, bounded discovery of flags in CUSTOM top-level ``C:\\`` dirs.

    Replaces the removed unbounded ``\\C$\\`` whole-drive walk. Steps:

    1. One cheap non-recursive listing of ``\\C$\\`` to find top-level dirs.
    2. Drop system dirs and dirs already covered by the dedicated roots.
    3. For each remaining CUSTOM dir (capped at ``TOP_LEVEL_MAX_DIRS``), run a
       depth-capped (``TOP_LEVEL_WALK_DEPTH``) bounded shallow walk under its
       own per-dir timeout.

    Pure SMB byte-read; no command-exec. Returns ``(root_path, WalkOutcome)``
    pairs (each already logged via :func:`_walk_root_logged`).
    """
    custom_dirs, list_err = await enumerate_top_level_dirs(conn)
    if list_err is not None:
        # enumerate_top_level_dirs already logged the OUTCOME line.
        return []
    if not custom_dirs:
        return []

    selected = custom_dirs[:TOP_LEVEL_MAX_DIRS]
    if len(custom_dirs) > TOP_LEVEL_MAX_DIRS:
        print_info_debug(
            f"[ctf-flags] top-level discovery: {len(custom_dirs)} custom dirs, "
            f"capping shallow walk to first {TOP_LEVEL_MAX_DIRS}"
        )

    outcomes: list[tuple[str, WalkOutcome]] = []
    for name in selected:
        root_path = f"\\C$\\{name}\\"
        masked = mark_sensitive(name, "path")
        print_info_debug(
            f"[ctf-flags] top-level discovery: shallow walk custom dir {masked} "
            f"(depth={TOP_LEVEL_WALK_DEPTH}, max_entries={TOP_LEVEL_WALK_MAX_ENTRIES})"
        )
        res = await _walk_root_logged(
            conn,
            root_path=root_path,
            per_root_timeout=per_dir_timeout,
            depth=TOP_LEVEL_WALK_DEPTH,
            max_entries=TOP_LEVEL_WALK_MAX_ENTRIES,
        )
        outcomes.append((root_path, res))
    return outcomes


async def smb_walk_bounded(
    *,
    config: SMBConfig,
    host: str,
    path_timeout_seconds: float,
    walk_timeout_seconds: float = WALK_TIMEOUT_SECONDS,
    connect_attempts_max: int = 2,
    connect_settle_seconds: float = 0.5,
) -> StrategyOutcome:
    """Run the bounded walk roots + shallow top-level discovery and read hits.

    The walk is the catch-all: it opens its own fresh SMB connection and can
    find a flag at ANY path, so when the fixed-path probes are inconclusive
    (NETWORK_ERROR rather than NOT_FOUND) it MUST get a real chance to run.

    Two complementary discovery mechanisms share the one connection:

    * The dedicated ``WALK_ROOTS`` (Users, inetpub, xampp) — deep but narrow.
    * A shallow top-level discovery that lists ``\\C$\\`` once and runs a
      depth-capped walk on each CUSTOM top-level dir (``share``, ``backup``,
      …). This replaces the old unbounded ``\\C$\\`` whole-drive walk that
      reliably blew the 25s cap and was silent when cancelled.

    Resilience: against a DC that aggressively resets SMB sessions the first
    connect / negotiate may fail to start — surfacing either as a transport
    error on open or as a fully-blank ``list_r`` (0 files, 0 dirs, 0 errored).
    Both are retried up to ``connect_attempts_max`` times with a
    ``connect_settle_seconds`` settle so a brand-new session is ready before
    the walk begins. A blank result on an already-open session is also
    retried in-session once (the long-standing race fix) before the walk
    gives up on that connection.
    """
    from adscan_internal.services.ctf_flag_collector import (
        FlagDiscoveryStrategy,
        FlagHit,
        FlagProbeError,
        FlagProbeOutcome,
        _hash_flag,
        _normalise_flag_value,
        _read_one_path,
    )
    from adscan_internal.services.ctf_flag_collector_catalog import (
        _kind_from_basename,
    )

    out = StrategyOutcome()

    files_scanned = 0
    dirs_traversed = 0
    dirs_excluded = 0
    hit_max = False
    candidate_paths: list[str] = []
    per_root_stats: list[dict] = []

    started_loop = asyncio.get_event_loop().time()

    # Per-root timeout for the dedicated deep roots: keep each root under the
    # overall walk budget so one slow root can't starve the rest and never
    # log. Leaves headroom for the top-level discovery phase.
    per_root_timeout = max(2.0, walk_timeout_seconds / max(1, len(WALK_ROOTS)))

    def _is_all_blank(results: list[tuple[str, object]]) -> bool:
        """True when every WalkOutcome returned 0 files + 0 dirs + 0 errored."""
        outcomes = [r for (_root, r) in results if isinstance(r, WalkOutcome)]
        if not outcomes:
            return False
        return all(
            r.files_scanned == 0 and r.dirs_traversed == 0 and r.entries_errored == 0
            for r in outcomes
        )

    async def _run_walk_tasks(conn) -> list[tuple[str, object]]:
        # Dedicated deep roots run in parallel; each is individually wrapped so
        # a per-root timeout/exception still logs an OUTCOME line.
        tasks = [
            asyncio.create_task(
                _walk_root_logged(conn, root_path=root, per_root_timeout=per_root_timeout),
                name=f"walk:{root}",
            )
            for root in WALK_ROOTS
        ]
        try:
            deep = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=walk_timeout_seconds,
            )
            return list(zip(WALK_ROOTS, deep))
        except asyncio.TimeoutError:
            for t in tasks:
                if not t.done():
                    t.cancel()
            out.errors.append(f"walk exceeded {walk_timeout_seconds:.0f}s timeout")
            # Every root that didn't finish must still log an OUTCOME line.
            results: list[tuple[str, object]] = []
            for root, t in zip(WALK_ROOTS, tasks):
                if t.done() and not t.cancelled() and t.exception() is None:
                    results.append((root, t.result()))
                    continue
                print_info_debug(
                    f"[ctf-flags] walk root={root} OUTCOME=cancelled "
                    "(parent walk-phase timeout) files=0 dirs=0 errored=0 candidates=0"
                )
                results.append((root, WalkOutcome([], 0, 0, 0, 0, False, "walk-phase timeout")))
            return results

    async def _run_all_discovery(conn) -> list[tuple[str, object]]:
        """Deep roots (parallel) + shallow top-level discovery (sequential)."""
        deep_results = await _run_walk_tasks(conn)
        # Shallow top-level discovery is cheap and bounded; run it after the
        # deep roots so the deep roots get their full parallel budget first.
        try:
            top_results: list[tuple[str, object]] = list(
                await _discover_top_level_walks(
                    conn, per_dir_timeout=TOP_LEVEL_PER_DIR_TIMEOUT_SECONDS
                )
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            out.errors.append(f"top-level discovery: {exc}")
            top_results = []
        return deep_results + top_results

    stderr_buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr_buf):
            walk_started = False
            connect_attempt = 0
            for connect_attempt in range(1, connect_attempts_max + 1):
                if connect_attempt > 1:
                    print_info_debug(
                        "[ctf-flags] walk: re-opening a fresh SMB connection "
                        f"(attempt {connect_attempt}/{connect_attempts_max}) "
                        f"after {connect_settle_seconds:.1f}s settle — previous "
                        "attempt did not start (transport reset or all-blank)"
                    )
                    await asyncio.sleep(connect_settle_seconds)
                else:
                    print_info_debug(
                        f"[ctf-flags] walk: opening SMB connection "
                        f"(attempt {connect_attempt}/{connect_attempts_max})"
                    )
                try:
                    async with smb_machine_with_fallback(config) as machine:
                        # Walk all roots in parallel sharing the connection —
                        # list_r is read-only metadata enumeration, no byte-read
                        # in flight, so concurrent walks on one connection are
                        # safe (unlike parallel get_file_data calls which were
                        # the original corruption case).
                        walk_results = await _run_all_discovery(machine.connection)

                        # In-session blank-retry (race fix): a freshly negotiated
                        # session may not be initialised when list_r begins; a
                        # short pause + one re-run on the SAME connection usually
                        # recovers it.
                        if _is_all_blank(walk_results):
                            print_info_debug(
                                "[ctf-flags] walk: all roots returned blank "
                                "(race fingerprint — session not settled). "
                                "Retrying in-session after 0.5s."
                            )
                            await asyncio.sleep(0.5)
                            walk_results = await _run_all_discovery(machine.connection)

                        # Still blank after the in-session retry: the connection
                        # itself may be wedged by the DC's reset. Re-open a fresh
                        # one if budget remains.
                        if _is_all_blank(walk_results) and (
                            connect_attempt < connect_attempts_max
                        ):
                            print_info_debug(
                                "[ctf-flags] walk: still blank after in-session "
                                "retry — re-opening a fresh connection"
                            )
                            continue

                        walk_started = True

                        # Accumulate per-root stats and dedup candidate paths.
                        seen_paths: set[str] = set()
                        for root, res in walk_results:
                            if isinstance(res, BaseException):
                                telemetry.capture_exception(res)
                                out.errors.append(f"walk root error: {res}")
                                per_root_stats.append({
                                    "root": root,
                                    "files_scanned": 0,
                                    "dirs_traversed": 0,
                                    "dirs_excluded": 0,
                                    "candidates_evaluated": 0,
                                    "elapsed_ms": 0,
                                    "error": str(res),
                                })
                                continue
                            if not isinstance(res, WalkOutcome):
                                continue
                            files_scanned += res.files_scanned
                            dirs_traversed += res.dirs_traversed
                            dirs_excluded += res.dirs_excluded
                            if res.hit_max_entries:
                                hit_max = True
                            if res.error:
                                out.errors.append(res.error)
                            per_root_stats.append({
                                "root": root,
                                "files_scanned": res.files_scanned,
                                "dirs_traversed": res.dirs_traversed,
                                "dirs_excluded": res.dirs_excluded,
                                "candidates_evaluated": len(res.candidates),
                                "elapsed_ms": 0,
                                "error": res.error,
                            })
                            for p in res.candidates:
                                if p not in seen_paths:
                                    seen_paths.add(p)
                                    candidate_paths.append(p)

                        # Read each candidate sequentially on this same session.
                        # Typical len(candidate_paths) is single digits, so this
                        # is cheap and avoids re-introducing parallel-read
                        # corruption.
                        for path in candidate_paths:
                            res = await _read_one_path(
                                machine,
                                path=path,
                                path_timeout_seconds=path_timeout_seconds,
                                max_attempts=2,
                            )
                            kind = _kind_from_basename(path)
                            if res.outcome.value == "success":
                                token = _normalise_flag_value(res.data)
                                if token is None:
                                    out.probe_errors.append(
                                        FlagProbeError(
                                            path=path,
                                            owner=None,
                                            kind=kind,
                                            outcome=FlagProbeOutcome.OTHER_ERROR,
                                            detail="content did not look like a flag",
                                            attempts=res.attempts,
                                            discovered_via=FlagDiscoveryStrategy.SMB_WALK,
                                        )
                                    )
                                    continue
                                out.hits.append(
                                    FlagHit(
                                        host=host,
                                        owner_user=None,
                                        kind=kind,
                                        path=path,
                                        value=token,
                                        flag_hash=_hash_flag(token),
                                        captured_at=datetime.now(timezone.utc),
                                        method="smb_read",
                                        discovered_via=FlagDiscoveryStrategy.SMB_WALK,
                                    )
                                )
                            else:
                                out.probe_errors.append(
                                    FlagProbeError(
                                        path=path,
                                        owner=None,
                                        kind=kind,
                                        outcome=res.outcome,
                                        detail=res.detail,
                                        attempts=res.attempts,
                                        discovered_via=FlagDiscoveryStrategy.SMB_WALK,
                                    )
                                )
                        break
                except SMBAuthError:
                    # Auth failures are definitive — re-opening won't help.
                    raise
                except (SMBAccessDeniedError, SMBTransportError) as exc:
                    # Connection-open / transport reset: this is the canonical
                    # "walk did not start" cause against a resetting DC. Retry
                    # with a settle if budget remains; otherwise record it.
                    if connect_attempt < connect_attempts_max:
                        print_info_debug(
                            f"[ctf-flags] walk: connection failed to start "
                            f"({exc}); retrying with a fresh connection"
                        )
                        continue
                    out.errors.append(f"smb connect failed: {exc}")

            print_info_debug(
                f"[ctf-flags] walk start outcome: started={walk_started} "
                f"after {connect_attempt} attempt(s); "
                f"files_scanned={files_scanned} dirs_traversed={dirs_traversed} "
                f"candidates={len(candidate_paths)}"
            )
    except SMBAuthError as exc:
        out.errors.append(f"smb auth failed: {exc}")
    except (SMBAccessDeniedError, SMBTransportError) as exc:
        out.errors.append(f"smb connect failed: {exc}")
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        out.errors.append(f"smb walk strategy: {exc}")

    elapsed_ms = int((asyncio.get_event_loop().time() - started_loop) * 1000)

    out.walk_stats = {
        "files_scanned": files_scanned,
        "dirs_traversed": dirs_traversed,
        "dirs_excluded": dirs_excluded,
        "candidates_evaluated": len(candidate_paths),
        "elapsed_ms": elapsed_ms,
        "hit_max_entries": hit_max,
        "per_root": per_root_stats,
    }

    # Drain any aiosmb stderr noise the redirect captured.
    captured = stderr_buf.getvalue()
    if captured:
        for line in captured.splitlines():
            s = line.strip()
            if s:
                out.aiosmb_stderr_lines.append(s)
                print_info_debug(f"[ctf-flags] aiosmb-stderr (walk): {s}")

    return out


# ---------------------------------------------------------------------------
# Strategy 4 — PowerShell recursive file search
# ---------------------------------------------------------------------------

# Flag filenames to search for.
_PS_SEARCH_NAMES = ("user.txt", "root.txt", "flag.txt", "system.txt",
                    "local.txt", "proof.txt")

# Roots to exclude when expanding to full-disk search.
_PS_SEARCH_EXCLUDE = (
    r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)",
    r"C:\ProgramData",
)

_PS_SEARCH_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
$names=@({names})
$found=@(Get-ChildItem -Path 'C:\Users' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {{ $names -contains $_.Name }})
if ($found.Count -eq 0) {{
    $exclude=@({exclude})
    $found=@(Get-ChildItem -Path 'C:\' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {{
            ($names -contains $_.Name) -and
            (-not ($exclude | Where-Object {{ $_.FullName.ToLower().StartsWith($_.ToLower()) }}))
        }})
}}
foreach ($f in $found) {{
    $c=Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
    if ($c -ne $null) {{
        [PSCustomObject]@{{path=$f.FullName;content=$c.Trim()}} | ConvertTo-Json -Compress
    }}
}}
""".strip()


async def powershell_search(
    *,
    config: SMBConfig,
    shell,
    host: str,
    timeout_seconds: int = 15,
) -> StrategyOutcome:
    """Strategy 4 — PowerShell recursive search for flag files.

    Phase 1: ``Get-ChildItem -Recurse`` under ``C:\\Users`` only (fast,
    covers all user desktops regardless of username).
    Phase 2: if phase 1 finds nothing, expands to ``C:\\`` excluding
    Windows / Program Files / ProgramData (slower but catches flags in
    non-standard locations like ``C:\\flags\\user.txt``).

    Returns one JSON object per found file; the content is validated as a
    flag value by the caller via ``_normalise_flag_value``.

    Runs the native ``execute_with_fallback`` cascade
    (SMBEXEC -> ATEXEC -> WINRM). ``timeout_seconds`` is the PER-METHOD
    budget: the SMB-based methods fail fast on a reset-happy DC, and the
    cascade then falls through to WinRM (PSRP / 5985) — a distinct
    transport that survives a DC that aggressively resets port-445
    sessions. Returns an empty :class:`StrategyOutcome` on any exec
    failure.
    """
    import json as _json
    from datetime import datetime, timezone
    from adscan_internal.services.ctf_flag_collector import (
        FlagDiscoveryStrategy,
        FlagHit,
        FlagProbeError,
        FlagProbeOutcome,
        _classify_discovery,
        _hash_flag,
        _normalise_flag_value,
    )
    from adscan_internal.services.ctf_flag_collector_catalog import _kind_from_basename

    out = StrategyOutcome()
    if shell is None:
        return out

    names_ps = ", ".join(f"'{n}'" for n in _PS_SEARCH_NAMES)
    exclude_ps = ", ".join(f"'{p}'" for p in _PS_SEARCH_EXCLUDE)
    script = _PS_SEARCH_SCRIPT.format(names=names_ps, exclude=exclude_ps)

    # Imports outside the try/except so AuthError is always bound in scope.
    try:
        from adscan_internal.services.remote_exec import (
            STDOUT_CASCADE,
            AuthError,
            execute_with_fallback,
        )
        from adscan_internal.services.ctf_flag_collector import _make_panel_callback
    except ImportError as exc:
        out.errors.append(f"ps_search import failed: {exc}")
        return out

    print_info_debug(
        f"[ctf-flags] ps_search: running PowerShell file search on {host}"
    )

    host_intel_cache = getattr(shell, "host_intel_cache", None)
    edr_intel = getattr(shell, "edr_intel", None)
    workspace_type = getattr(shell, "type", None)
    on_intel = (
        _make_panel_callback(shell, host_intel_cache, workspace_type)
        if host_intel_cache is not None else None
    )

    try:
        result = await execute_with_fallback(
            config,
            script,
            methods=None if host_intel_cache is not None else STDOUT_CASCADE,
            intel_cache=host_intel_cache,
            intel=edr_intel,
            workspace_type=workspace_type,
            on_intel_resolved=on_intel,
            timeout=timeout_seconds,
        )
    except AuthError as exc:
        out.errors.append(f"ps_search auth failed: {exc}")
        return out
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        out.errors.append(f"ps_search exec failed: {exc}")
        return out

    if not result.success:
        detail = "; ".join(
            f"{f.method}={f.error_kind}: {f.message}" for f in result.errors
        )
        out.errors.append(f"ps_search cascade failed: {detail}")
        return out

    # Parse one JSON object per output line.
    stdout = result.stdout or ""
    found_count = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = _json.loads(line)
        except _json.JSONDecodeError:
            continue
        win_path = str(entry.get("path") or "").strip()
        content = str(entry.get("content") or "").strip()
        if not win_path or not content:
            continue

        # Normalise to share path form (\C$\...) for consistency with SMB hits.
        share_path = "\\C$" + win_path[2:] if win_path.lower().startswith("c:") else win_path

        token = _normalise_flag_value(content)
        basename = win_path.rsplit("\\", 1)[-1].lower()
        kind = _kind_from_basename(basename) or "unknown"

        print_info_debug(
            f"[ctf-flags] ps_search found: {share_path} kind={kind} "
            f"value={token[:8] if token else 'None'}…"
        )

        if token:
            found_count += 1
            owner = win_path.split("\\")[3] if win_path.lower().startswith("c:\\users\\") else None
            out.hits.append(
                FlagHit(
                    host=host,
                    path=share_path,
                    owner_user=owner,
                    kind=kind,
                    value=token,
                    flag_hash=_hash_flag(token),
                    captured_at=datetime.now(timezone.utc),
                    method=str(result.method) if result.method else "remote_exec",
                    discovered_via=_classify_discovery(share_path),
                )
            )
        else:
            out.probe_errors.append(
                FlagProbeError(
                    path=share_path,
                    owner=None,
                    kind=kind,
                    outcome=FlagProbeOutcome.OTHER_ERROR,
                    detail=f"content found but not a valid flag: {content[:32]!r}",
                    attempts=1,
                    discovered_via=FlagDiscoveryStrategy.POWERSHELL_SEARCH,
                )
            )

    print_info_debug(
        f"[ctf-flags] ps_search complete: {found_count} flag(s) found"
    )
    return out


__all__ = [
    "StrategyOutcome",
    "powershell_search",
    "probe_conventional",
    "probe_alternative",
    "smb_walk_bounded",
]
