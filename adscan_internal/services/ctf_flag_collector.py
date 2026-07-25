"""Native-first CTF flag collector.

Reads HTB / THM flag files (``user.txt``, ``root.txt``, ``system.txt``)
directly from the target host's ``C$`` share via aiosmb byte-streaming.
Falls back to the :mod:`remote_exec` cascade only when the byte-read
path returns ACCESS_DENIED for a candidate file.

Design notes (post flapping incident on HTB Forest):

* Probes are run **sequentially** within a single ``SMBMachine`` session.
  Parallel ``asyncio.gather`` over a single SMB session corrupts the
  session if any read fails — subsequent reads then trip aiosmb's bare
  ``socket.send() raised exception.`` ``print()`` and silently turn into
  spurious "not found" rows. Latency for ~6 paths is sub-second; the
  correctness gain is total. Cross-host parallelism still belongs at the
  caller layer.
* Every probe is classified into a :class:`FlagProbeOutcome` and
  retryable outcomes (``NETWORK_ERROR``, ``TIMEOUT``, ``OTHER_ERROR``)
  retry with linear backoff. ``NOT_FOUND`` and ``ACCESS_DENIED`` are
  definitive — no retry.
* If the SMB session itself is dead (≥2 consecutive ``NETWORK_ERROR``
  outcomes), the collector reconnects a small bounded number of times per
  run (``max_reconnects``), waiting a brief settle between attempts so the
  fresh aiosmb session is ready, then re-probes the still-pending candidates
  (conventional Desktop paths first). This survives DCs that aggressively
  reset SMB sessions mid-batch.
* aiosmb prints ``socket.send() raised exception.`` straight to stderr
  via bare ``print()`` calls. We capture the entire SMB block's stderr
  and re-emit captured lines via ``print_info_debug`` — the user TTY
  stays clean.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import re
import sys
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, Literal, Sequence

from adscan_internal import (
    print_info,
    print_info_debug,
    print_info_verbose,
    telemetry,
)
from adscan_internal.services.remote_exec import (
    STDOUT_CASCADE,
    AuthError,
    ExecMethod,
    execute_with_fallback,
)
from adscan_internal import get_console
from adscan_internal.services.smb_transport import (
    SMBAccessDeniedError,
    SMBAuthError,
    SMBConfig,
    SMBTransportError,
    smb_machine_with_fallback,
)
from adscan_core.rich_output import print_exception

FlagKind = Literal["user", "root", "system", "flag", "proof", "unknown"]
FlagMethod = Literal["smb_read", "remote_exec"]


class FlagDiscoveryStrategy(str, Enum):
    """Which strategy surfaced a given hit / probe error."""

    CONVENTIONAL = "conventional"      # Desktop standard locations
    ALTERNATIVE = "alternative"        # Known non-Desktop catalog
    SMB_WALK = "smb_walk"              # Discovered via recursive SMB scan
    POWERSHELL_SEARCH = "ps_search"    # PowerShell recursive file search


# Conventional Desktop pattern (case-insensitive). Anything matching this
# is a "regular" CTF location even if the SMB walk strategy was the one
# that surfaced it first — so it must NOT show up in the
# UNCONVENTIONAL panel. The classifier below is the single point of
# truth for "what kind of location is this?" and is intentionally
# decoupled from which strategy emitted the hit.
_CONVENTIONAL_DESKTOP_RE = re.compile(
    r"^/c\$/users/[^/]+/desktop/(user|root|system)\.txt$",
    re.IGNORECASE,
)


def _classify_discovery(path: str) -> "FlagDiscoveryStrategy":
    """Classify a flag path by its location, regardless of who found it.

    The strategy that *yielded* a hit can be misleading: the bounded
    SMB walk often beats the conventional probe to a path under
    ``\\Users\\<owner>\\Desktop\\``. From the operator's perspective
    that is still a conventional location — the box author put it where
    everyone expects. The UNCONVENTIONAL panel is reserved for hits
    whose **path** is genuinely off-Desktop.
    """
    if not path:
        return FlagDiscoveryStrategy.SMB_WALK
    normalized = path.replace("\\", "/").lower()
    if _CONVENTIONAL_DESKTOP_RE.match(normalized):
        return FlagDiscoveryStrategy.CONVENTIONAL
    # Alternative catalog: compare with case-insensitive equality on the
    # normalised path (catalog entries use backslashes).
    try:
        from adscan_internal.services.ctf_flag_collector_catalog import (
            ALTERNATIVE_FLAG_PATHS,
            PER_OWNER_ALTERNATIVE_TEMPLATES,
        )
        catalog_norms = {
            entry.replace("\\", "/").lower() for entry in ALTERNATIVE_FLAG_PATHS
        }
        if normalized in catalog_norms:
            return FlagDiscoveryStrategy.ALTERNATIVE
        # Per-owner templates: replace the {user} placeholder with a
        # path-segment regex AFTER escaping the rest of the literal so
        # characters like ``$`` or ``.`` don't get reinterpreted.
        sentinel = "\x00USER\x00"
        for tmpl in PER_OWNER_ALTERNATIVE_TEMPLATES:
            normalized_tmpl = tmpl.replace("\\", "/").lower()
            shape = normalized_tmpl.replace("{user}", sentinel)
            shape = re.escape(shape).replace(sentinel, "[^/]+")
            if re.fullmatch(shape, normalized):
                return FlagDiscoveryStrategy.ALTERNATIVE
    except Exception:  # noqa: BLE001
        pass
    return FlagDiscoveryStrategy.SMB_WALK



# Permissive token regex — HTB uses 32-hex MD5-style strings, but other
# CTFs use base64 / longer tokens. Accept any single-line printable
# token of length 8–128 with no whitespace.
_TOKEN_RE = re.compile(r"^[\x21-\x7E]{8,128}$")
_HEX32_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)


class FlagProbeOutcome(str, Enum):
    """Per-path probe outcome (mutually exclusive)."""

    SUCCESS = "success"
    NOT_FOUND = "not_found"
    ACCESS_DENIED = "access_denied"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    OTHER_ERROR = "other_error"


@dataclass(frozen=True, slots=True)
class FlagHit:
    """One captured flag plus provenance.

    Attributes:
        host: The host the flag was read from.
        owner_user: Name of the Desktop owner (``None`` if unknown).
        kind: ``user`` / ``root`` / ``system`` / ``flag`` / ``proof`` / ``unknown``.
        path: Remote path the flag was read from (UNC-like, no host).
        value: Raw flag content. Persisted to the workspace; never
            shown in panels by default.
        flag_hash: Short SHA-256 prefix used for screenshot-safe panels.
        captured_at: Timestamp the flag was read.
        method: Which transport path produced the hit.
        discovered_via: Which discovery strategy surfaced this hit.
    """

    host: str
    owner_user: str | None
    kind: FlagKind
    path: str
    value: str
    flag_hash: str
    captured_at: datetime
    method: FlagMethod
    discovered_via: FlagDiscoveryStrategy = FlagDiscoveryStrategy.CONVENTIONAL


@dataclass(frozen=True, slots=True)
class FlagProbeError:
    """Diagnostic record for a path probe that did not yield a hit."""

    path: str
    owner: str | None
    kind: FlagKind
    outcome: FlagProbeOutcome
    detail: str
    attempts: int
    discovered_via: FlagDiscoveryStrategy = FlagDiscoveryStrategy.CONVENTIONAL


@dataclass(frozen=True, slots=True)
class WalkRootStats:
    """Per-root diagnostics from one walk root.

    Attributes:
        root: Share-relative root path (e.g. ``\\C$\\Users\\``).
        files_scanned: Number of file entries observed under this root.
        dirs_traversed: Number of directories descended into.
        dirs_excluded: Number of directories skipped via the exclude list.
        candidates_evaluated: Number of flag-candidate names matched.
        elapsed_ms: Wall-clock time spent walking this root.
        error: ``None`` on success, error string if this root failed.
    """

    root: str
    files_scanned: int
    dirs_traversed: int
    dirs_excluded: int
    candidates_evaluated: int
    elapsed_ms: int
    error: str | None = None


@dataclass(frozen=True, slots=True)
class WalkStats:
    """Aggregate diagnostics from the bounded SMB walk strategy."""

    files_scanned: int
    dirs_traversed: int
    dirs_excluded: int
    candidates_evaluated: int
    elapsed_ms: int
    hit_max_entries: bool
    per_root: tuple[WalkRootStats, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class FlagCollectionResult:
    """Aggregated outcome of one :func:`collect_ctf_flags` run."""

    hits: tuple[FlagHit, ...]
    elapsed_ms: int
    primary_strategy: FlagMethod
    fallback_used: bool
    fallback_method: ExecMethod | None = None
    errors: tuple[str, ...] = field(default_factory=tuple)
    probes: tuple[FlagProbeError, ...] = field(default_factory=tuple)
    walk_stats: WalkStats | None = None


# ---------------------------------------------------------------------------
# Candidate building
# ---------------------------------------------------------------------------

_DEFAULT_FALLBACK_USERS: tuple[str, ...] = ("Administrator",)

# System-managed folders that exist in C:\Users\ but never contain flags.
_USERS_DIR_SKIP: frozenset[str] = frozenset({
    "default", "default user", "all users", "public", "desktop.ini",
})


async def _enumerate_users_from_smb(config) -> list[str]:
    """List real user profile folders under ``C$\\Users\\``.

    Returns folder names (e.g. ``["adam.silver", "Administrator", "levi.james"]``).
    Returns an empty list on any error — caller falls back to the credential list.
    This is more reliable than credential-based candidates: only folders that
    actually exist on disk, no NOT_FOUND noise for non-existent profiles.
    """
    try:
        from aiosmb.commons.interfaces.directory import SMBDirectory
        from adscan_internal.services.smb_transport import smb_machine_with_fallback

        async with smb_machine_with_fallback(config) as machine:
            directory = SMBDirectory.from_remotepath(
                machine.connection, r"\C$\Users\\"
            )
            _, err = await directory.open(machine.connection)  # pylint: disable=no-member
            if err:
                return []
            seen: set[str] = set()
            result: list[str] = []
            async for obj, otype, entry_err in directory.list_r(
                machine.connection, depth=1, maxentries=200
            ):
                if entry_err or otype != "dir":
                    continue
                name = str(getattr(obj, "name", "") or "").strip()
                if not name or name.lower() in _USERS_DIR_SKIP:
                    continue
                if name.lower() not in seen:
                    seen.add(name.lower())
                    result.append(name)
            return result
    except Exception:
        return []


def _candidate_users(
    *, shell, domain: str, candidate_users: Sequence[str] | None
) -> tuple[list[str], str]:
    """Build the list of usernames whose Desktop should be probed.

    Returns:
        Tuple ``(users, source)`` where ``source`` is one of
        ``"explicit"`` (caller passed ``candidate_users``),
        ``"shell_workspace"`` (derived from the shell's workspace data),
        or ``"default_admin_only"`` (Administrator fallback only).
    """
    seen: set[str] = set()
    out: list[str] = []

    def _push(name: str | None) -> bool:
        if not name:
            return False
        clean = str(name).strip()
        if not clean or "\\" in clean or "/" in clean:
            return False
        key = clean.lower()
        if key in seen:
            return False
        seen.add(key)
        out.append(clean)
        return True

    explicit_pushed = False
    if candidate_users:
        for n in candidate_users:
            if _push(n):
                explicit_pushed = True

    workspace_pushed = False
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict):
        domain_entry = domains_data.get(domain) or {}
        if isinstance(domain_entry, dict):
            for u in domain_entry.get("users", []) or []:
                if isinstance(u, str):
                    if _push(u):
                        workspace_pushed = True
                elif isinstance(u, dict):
                    if _push(u.get("username") or u.get("name")):
                        workspace_pushed = True
            if _push(domain_entry.get("username")):
                workspace_pushed = True
            # Include all users from the credentials store — these are known
            # compromised accounts that may own flag files (e.g. adam.silver
            # in Puppy has user.txt on their Desktop but is not in "users" list).
            for cred_user in (domain_entry.get("credentials") or {}).keys():
                if isinstance(cred_user, str) and _push(cred_user):
                    workspace_pushed = True

    for fallback in _DEFAULT_FALLBACK_USERS:
        _push(fallback)

    if explicit_pushed:
        source = "explicit"
    elif workspace_pushed:
        source = "shell_workspace"
    else:
        source = "default_admin_only"
    return out, source


def _candidate_paths(users: Iterable[str]) -> list[tuple[str, FlagKind, str]]:
    """Return ``(unc_path, kind, owner_user)`` triples to probe.

    Paths are share-relative — ``smb_machine_for`` resolves them under
    ``C$`` via ``SMBFile.from_remotepath`` (which expects ``\\share\\…``
    style paths).
    """
    out: list[tuple[str, FlagKind, str]] = []
    for user in users:
        out.append((rf"\C$\Users\{user}\Desktop\user.txt", "user", user))
        out.append((rf"\C$\Users\{user}\Desktop\root.txt", "root", user))
        out.append((rf"\C$\Users\{user}\Desktop\system.txt", "system", user))
    return out


def _prioritize_conventional_first(
    candidates: list[tuple[str, "FlagKind", str]],
) -> list[tuple[str, "FlagKind", str]]:
    r"""Reorder candidates so conventional Desktop paths are probed first.

    Used on reconnect: when an SMB session dies mid-batch we want the
    highest-value standard locations (the conventional ``Users\<user>\
    Desktop\*.txt`` paths) re-probed on the fresh session before any
    lower-value paths, so a tight
    reconnect budget is never spent on long-shot paths while the actual
    flag location goes unread. Order within each group is preserved (stable).
    """
    desktop: list[tuple[str, "FlagKind", str]] = []
    other: list[tuple[str, "FlagKind", str]] = []
    for entry in candidates:
        path = entry[0] or ""
        normalized = path.replace("\\", "/").lower()
        if _CONVENTIONAL_DESKTOP_RE.match(normalized):
            desktop.append(entry)
        else:
            other.append(entry)
    return desktop + other


# ---------------------------------------------------------------------------
# Validation + parsing helpers
# ---------------------------------------------------------------------------


def _normalise_flag_value(raw: bytes | str) -> str | None:
    """Validate raw bytes/str as a flag and return the canonical token.

    Accepts BOTH ``bytes`` (SMB byte-read, or WinRM stdout the caller already
    ``.encode()``-ed) AND ``str`` (an already-decoded value, e.g. the JSON
    ``content`` field from the PowerShell-search fallback). The str path is the
    one that bit us: when this body was bytes-only, a str caller hit
    ``str.decode`` → ``AttributeError`` → swallowed by the bare ``except`` →
    EVERY ps_search flag silently rejected as "not a valid flag", losing flags
    only reachable via that fallback (e.g. domain-suffixed user profiles the
    SMB walk times out on). Handling both types here fixes it at the right
    layer and kills the whole class of bug.

    Returns:
        The validated token, or ``None`` if the input does not look like
        a flag (multi-line, too short/long, non-printable).
    """
    if not raw:
        return None
    if isinstance(raw, str):
        text = raw.strip()
    else:
        try:
            text = raw.decode("utf-8", errors="replace").strip()
        except Exception:  # noqa: BLE001
            return None
    if not text:
        return None
    line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    if not line:
        return None
    if _TOKEN_RE.match(line):
        return line
    m = _HEX32_RE.search(line)
    if m:
        return m.group(0)
    return None


def _hash_flag(value: str) -> str:
    """Short SHA-256 prefix used in screenshot-safe panels."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return digest[:16]


# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------


_NOT_FOUND_MARKERS: tuple[str, ...] = (
    "object_name_not_found",
    "no such file",
    "not_found",
    "0xc0000034",
    "status_object_path_not_found",
    "0xc000003a",
    "filenotfounderror",
)
_ACCESS_DENIED_MARKERS: tuple[str, ...] = (
    "access_denied",
    "access denied",
    "0xc0000022",
)
_NETWORK_MARKERS: tuple[str, ...] = (
    "socket.send",
    "socket closed",
    "connection reset",
    "broken pipe",
    "eof",
    "connection refused",
    "connection aborted",
    "network is unreachable",
    "host is unreachable",
    "no route to host",
    "connection lost",
)


def _classify_error(detail: str | BaseException) -> FlagProbeOutcome:
    """Classify an SMB read error string / exception into a probe outcome.

    Pure function — used by L1 tests.
    """
    if isinstance(detail, asyncio.TimeoutError):
        return FlagProbeOutcome.TIMEOUT
    if isinstance(detail, FileNotFoundError):
        return FlagProbeOutcome.NOT_FOUND
    if isinstance(detail, (ConnectionError, OSError)):
        # Treat OSError / ConnectionError as transient — message classifier
        # below will further refine if ACCESS_DENIED slipped through.
        text = str(detail).lower()
        if any(m in text for m in _ACCESS_DENIED_MARKERS):
            return FlagProbeOutcome.ACCESS_DENIED
        if any(m in text for m in _NOT_FOUND_MARKERS):
            return FlagProbeOutcome.NOT_FOUND
        return FlagProbeOutcome.NETWORK_ERROR
    text = str(detail).lower()
    if not text:
        return FlagProbeOutcome.OTHER_ERROR
    if any(m in text for m in _NOT_FOUND_MARKERS):
        return FlagProbeOutcome.NOT_FOUND
    if any(m in text for m in _ACCESS_DENIED_MARKERS):
        return FlagProbeOutcome.ACCESS_DENIED
    if "timeout" in text or "timed out" in text:
        return FlagProbeOutcome.TIMEOUT
    if any(m in text for m in _NETWORK_MARKERS):
        return FlagProbeOutcome.NETWORK_ERROR
    return FlagProbeOutcome.OTHER_ERROR


def _is_retryable(outcome: FlagProbeOutcome) -> bool:
    """Whether a given outcome should trigger a retry."""
    return outcome in (
        FlagProbeOutcome.NETWORK_ERROR,
        FlagProbeOutcome.TIMEOUT,
        FlagProbeOutcome.OTHER_ERROR,
    )


# ---------------------------------------------------------------------------
# SMB byte-read primitive
# ---------------------------------------------------------------------------


async def _read_bytes_via_smb(
    machine, share_path: str, *, max_bytes: int = 4096
) -> tuple[bytes, str | None]:
    """Read up to ``max_bytes`` of ``share_path`` via an open SMBMachine.

    Returns ``(bytes, error_message_or_none)``.
    """
    try:
        from aiosmb.commons.interfaces.file import SMBFile
    except ImportError as exc:
        return b"", f"aiosmb not available: {exc}"

    file_obj = SMBFile.from_remotepath(machine.connection, share_path)
    buf = bytearray()
    try:
        async for chunk, err in machine.get_file_data(file_obj):
            if err is not None:
                return bytes(buf), str(err)
            if not chunk:
                continue
            remaining = max_bytes - len(buf)
            if remaining <= 0:
                break
            if len(chunk) > remaining:
                buf.extend(chunk[:remaining])
                break
            buf.extend(chunk)
    except RuntimeError as exc:
        # aiosmb ≤ 0.4.14 leaks StopIteration → RuntimeError on EOF.
        if not (exc.__cause__ and isinstance(exc.__cause__, StopIteration)):
            return bytes(buf), str(exc)
    except Exception as exc:  # noqa: BLE001
        return bytes(buf), str(exc)
    return bytes(buf), None


# ---------------------------------------------------------------------------
# Per-path probe with retry + classification
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _ProbeResult:
    """Internal result for one path probe (post-retry)."""

    outcome: FlagProbeOutcome
    detail: str
    data: bytes
    attempts: int
    elapsed_ms: int


async def _read_one_path(
    machine,
    *,
    path: str,
    path_timeout_seconds: float,
    max_attempts: int,
    backoff_seconds: float = 0.5,
) -> _ProbeResult:
    """Read one path with retries on retryable outcomes.

    Args:
        machine: An open ``SMBMachine`` instance.
        path: Share-relative path (e.g. ``\\C$\\Users\\X\\Desktop\\user.txt``).
        path_timeout_seconds: Per-attempt timeout.
        max_attempts: Total attempts (1 = no retry).
        backoff_seconds: Linear backoff multiplier between retries.

    Returns:
        :class:`_ProbeResult` carrying the final outcome, classified
        detail, raw bytes (on SUCCESS) and attempt count.
    """
    started = asyncio.get_event_loop().time()
    last_detail = ""
    attempt = 0
    for attempt in range(1, max_attempts + 1):
        try:
            data, err = await asyncio.wait_for(
                _read_bytes_via_smb(machine, path),
                timeout=path_timeout_seconds,
            )
        except asyncio.TimeoutError:
            outcome = FlagProbeOutcome.TIMEOUT
            last_detail = f"timeout {path_timeout_seconds:.1f}s"
            print_info_debug(
                f"[ctf-flags] probe {path} -> TIMEOUT "
                f"retry {attempt}/{max_attempts} ({last_detail})"
            )
            if attempt < max_attempts:
                await asyncio.sleep(backoff_seconds * attempt)
                continue
            elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
            print_info_debug(
                f"[ctf-flags] probe {path} -> TIMEOUT final (max attempts reached)"
            )
            return _ProbeResult(outcome, last_detail, b"", attempt, elapsed_ms)
        except Exception as exc:  # noqa: BLE001
            outcome = _classify_error(exc)
            last_detail = str(exc)
            if not _is_retryable(outcome) or attempt >= max_attempts:
                elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
                print_info_debug(
                    f"[ctf-flags] probe {path} -> {outcome.name} ({last_detail})"
                )
                return _ProbeResult(outcome, last_detail, b"", attempt, elapsed_ms)
            print_info_debug(
                f"[ctf-flags] probe {path} -> {outcome.name} "
                f"retry {attempt}/{max_attempts} ({last_detail})"
            )
            await asyncio.sleep(backoff_seconds * attempt)
            continue

        if err is None:
            elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
            print_info_debug(
                f"[ctf-flags] probe {path} -> SUCCESS "
                f"({len(data)} bytes, {elapsed_ms}ms)"
            )
            return _ProbeResult(
                FlagProbeOutcome.SUCCESS, "ok", data, attempt, elapsed_ms
            )

        outcome = _classify_error(err)
        last_detail = err
        if not _is_retryable(outcome):
            elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
            print_info_debug(
                f"[ctf-flags] probe {path} -> {outcome.name} ({err})"
            )
            return _ProbeResult(outcome, last_detail, b"", attempt, elapsed_ms)
        if attempt < max_attempts:
            print_info_debug(
                f"[ctf-flags] probe {path} -> {outcome.name} "
                f"retry {attempt}/{max_attempts} ({err})"
            )
            await asyncio.sleep(backoff_seconds * attempt)
            continue
        elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
        print_info_debug(
            f"[ctf-flags] probe {path} -> {outcome.name} final (max attempts reached)"
        )
        return _ProbeResult(outcome, last_detail, b"", attempt, elapsed_ms)

    # Unreachable, but keeps type-checker happy.
    elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
    return _ProbeResult(
        FlagProbeOutcome.OTHER_ERROR, last_detail, b"", attempt, elapsed_ms
    )


# ---------------------------------------------------------------------------
# Stderr capture for aiosmb's bare print() calls
# ---------------------------------------------------------------------------


def _drain_aiosmb_stderr(buf: io.StringIO) -> None:
    """Forward captured aiosmb stderr lines to ``print_info_debug``."""
    text = buf.getvalue()
    if not text:
        return
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        print_info_debug(f"[ctf-flags] aiosmb-stderr: {s}")


# ---------------------------------------------------------------------------
# Sequential SMB byte-read strategy with classification + reconnect
# ---------------------------------------------------------------------------


async def _smb_byte_read_strategy(
    *,
    config: SMBConfig,
    candidates: list[tuple[str, FlagKind, str]],
    path_timeout_seconds: float,
    host: str,
    max_attempts: int = 3,
    max_reconnects: int = 4,
    reconnect_settle_seconds: float = 0.5,
    total_budget_seconds: float = 24.0,
    discovered_via: "FlagDiscoveryStrategy" = None,  # type: ignore[assignment]
) -> tuple[
    list[FlagHit],
    list[tuple[str, FlagKind, str, str]],
    list[FlagProbeError],
    list[str],
]:
    """Run the SMB byte-read path **sequentially** within one session.

    Returns ``(hits, denied_candidates, probe_errors, errors)``:

    * ``hits`` — FlagHit list.
    * ``denied_candidates`` — ``(path, kind, owner, detail)`` tuples for
      ACCESS_DENIED outcomes (caller decides whether to fall back).
    * ``probe_errors`` — :class:`FlagProbeError` for every non-SUCCESS
      probe (including NOT_FOUND, useful for the panel).
    * ``errors`` — non-recoverable connection-level issues (panel footer).

    Resilience model (hardened for DCs that aggressively reset SMB
    sessions): when the live session looks dead the loop reconnects up to
    ``max_reconnects`` times, sleeping ``reconnect_settle_seconds`` between
    attempts so the fresh aiosmb session has settled before re-probing.
    Paths that errored with ``NETWORK_ERROR`` on a dead session are NOT
    terminal — they are re-probed on the new session, with the highest-value
    conventional Desktop paths re-prioritised first. Remaining candidates are
    only marked ``NETWORK_ERROR`` once the reconnect budget is genuinely
    exhausted.

    ``total_budget_seconds`` is a wall-clock cap on the whole strategy
    (connect + probes + every reconnect). It guarantees the reconnect loop
    actually gets to re-probe the pending Desktop paths instead of letting a
    single dead path consume the caller's hard cap via the per-path retry
    budget — the root cause of the "conventional probed=0" symptom against a
    DC that aggressively resets SMB sessions.
    """
    if discovered_via is None:
        discovered_via = FlagDiscoveryStrategy.CONVENTIONAL
    hits: list[FlagHit] = []
    denied: list[tuple[str, FlagKind, str, str]] = []
    probe_errors: list[FlagProbeError] = []
    errors: list[str] = []

    pending: list[tuple[str, FlagKind, str]] = list(candidates)
    reconnects_used = 0
    # Wall-clock deadline for the whole strategy (connect + probes +
    # reconnects). Without this guard the per-path retry budget
    # (max_attempts x path_timeout) could burn the caller's hard cap on a
    # single dead path before any reconnect re-probes the pending Desktop
    # paths — the root cause of the "conventional probed=0" bug on a
    # reset-happy DC.
    strategy_started = asyncio.get_event_loop().time()

    def _budget_remaining() -> float:
        return total_budget_seconds - (
            asyncio.get_event_loop().time() - strategy_started
        )

    stderr_buf = io.StringIO()

    async def _run_session(
        candidate_slice: list[tuple[str, FlagKind, str]],
    ) -> tuple[bool, list[tuple[str, FlagKind, str]]]:
        """Open one SMB session and drain ``candidate_slice`` sequentially.

        Returns ``(session_died, remaining)``:

        * ``session_died=True`` if the session looks dead (≥2 consecutive
          NETWORK_ERROR / TIMEOUT outcomes) — caller may try one reconnect.
        * ``remaining`` — candidates that still need a verdict: the unprobed
          tail plus any path that failed with NETWORK_ERROR / TIMEOUT during
          the consecutive run that tripped the death detector. Those
          transient failures are NOT recorded as terminal here — a fresh
          session gets to re-probe them. Empty if everything was probed to a
          definitive verdict.
        """
        consecutive_net_errors = 0
        # Paths that failed with NETWORK_ERROR / TIMEOUT in the *current*
        # consecutive run. They are held back (no terminal probe_error) so a
        # reconnect can re-probe them; flushed to terminal probe_errors only
        # when the run is broken by a definitive outcome (the failures were
        # isolated, session is healthy) or by the caller once the reconnect
        # budget is exhausted.
        consecutive_net_paths: list[tuple[str, FlagKind, str]] = []

        def _flush_transient_as_terminal() -> None:
            """Record held-back transient failures as terminal NETWORK_ERROR."""
            for _p, _k, _o in consecutive_net_paths:
                probe_errors.append(
                    FlagProbeError(
                        path=_p, owner=_o or None, kind=_k,
                        outcome=FlagProbeOutcome.NETWORK_ERROR,
                        detail="transient SMB failure on a healthy session",
                        attempts=max_attempts,
                        discovered_via=discovered_via,
                    )
                )
            consecutive_net_paths.clear()

        try:
            async with smb_machine_with_fallback(config) as machine:
                while candidate_slice:
                    path, kind, owner = candidate_slice[0]
                    res = await _read_one_path(
                        machine,
                        path=path,
                        path_timeout_seconds=path_timeout_seconds,
                        max_attempts=max_attempts,
                    )
                    if res.outcome is FlagProbeOutcome.SUCCESS:
                        consecutive_net_errors = 0
                        _flush_transient_as_terminal()
                        token = _normalise_flag_value(res.data)
                        if token is None:
                            probe_errors.append(
                                FlagProbeError(
                                    path=path,
                                    owner=owner or None,
                                    kind=kind,
                                    outcome=FlagProbeOutcome.OTHER_ERROR,
                                    detail="content did not look like a flag",
                                    attempts=res.attempts,
                                    discovered_via=discovered_via,
                                )
                            )
                        else:
                            hits.append(
                                FlagHit(
                                    host=host,
                                    owner_user=owner or None,
                                    kind=kind,
                                    path=path,
                                    value=token,
                                    flag_hash=_hash_flag(token),
                                    captured_at=datetime.now(timezone.utc),
                                    method="smb_read",
                                    discovered_via=discovered_via,
                                )
                            )
                        candidate_slice.pop(0)
                        continue

                    if res.outcome is FlagProbeOutcome.ACCESS_DENIED:
                        consecutive_net_errors = 0
                        _flush_transient_as_terminal()
                        denied.append((path, kind, owner, res.detail))
                        probe_errors.append(
                            FlagProbeError(
                                path=path, owner=owner or None, kind=kind,
                                outcome=res.outcome, detail=res.detail,
                                attempts=res.attempts,
                                discovered_via=discovered_via,
                            )
                        )
                        candidate_slice.pop(0)
                        continue

                    if res.outcome is FlagProbeOutcome.NOT_FOUND:
                        consecutive_net_errors = 0
                        _flush_transient_as_terminal()
                        probe_errors.append(
                            FlagProbeError(
                                path=path, owner=owner or None, kind=kind,
                                outcome=res.outcome, detail=res.detail,
                                attempts=res.attempts,
                                discovered_via=discovered_via,
                            )
                        )
                        candidate_slice.pop(0)
                        continue

                    # NETWORK_ERROR / TIMEOUT / OTHER_ERROR after exhausting
                    # per-path retries — decide whether the session is dead.
                    if res.outcome in (
                        FlagProbeOutcome.NETWORK_ERROR,
                        FlagProbeOutcome.TIMEOUT,
                    ):
                        # Hold the path back instead of recording a terminal
                        # probe_error: if the session turns out to be dead, a
                        # reconnect must get to re-probe it. Only flushed to
                        # terminal once it is clearly an isolated transient
                        # (healthy session) or the reconnect budget is spent.
                        candidate_slice.pop(0)
                        consecutive_net_paths.append((path, kind, owner))
                        consecutive_net_errors += 1
                        if consecutive_net_errors >= 2:
                            # Session looks dead — carry the suspect transient
                            # failures AND the unprobed tail to the reconnect.
                            return True, consecutive_net_paths + candidate_slice
                    else:
                        # OTHER_ERROR — a real per-path failure, not a transport
                        # death signal. Record terminal and treat the prior
                        # transient run as isolated/healthy.
                        consecutive_net_errors = 0
                        _flush_transient_as_terminal()
                        probe_errors.append(
                            FlagProbeError(
                                path=path, owner=owner or None, kind=kind,
                                outcome=res.outcome, detail=res.detail,
                                attempts=res.attempts,
                                discovered_via=discovered_via,
                            )
                        )
                        candidate_slice.pop(0)
        except SMBAuthError:
            raise
        except SMBAccessDeniedError as exc:
            errors.append(f"connection denied: {exc}")
            _flush_transient_as_terminal()
            return False, candidate_slice
        except SMBTransportError as exc:
            errors.append(f"connection failed: {exc}")
            # Transport death — carry held-back transient failures and the
            # unprobed tail to the reconnect; do not record them terminal yet.
            carry = consecutive_net_paths + candidate_slice
            return bool(carry), carry
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            errors.append(f"unexpected error: {exc}")
            carry = consecutive_net_paths + candidate_slice
            return bool(carry), carry
        # Drained the slice without tripping the death detector. Any lingering
        # single transient failure is isolated → record it terminal now.
        _flush_transient_as_terminal()
        return False, candidate_slice

    # Capture aiosmb's bare `print()` noise (`socket.send() raised exception.`)
    # to debug only — it must never reach the user TTY.
    with contextlib.redirect_stderr(stderr_buf):
        session_died, pending = await _run_session(pending)
        # Reconnect while the session keeps dying AND there are still
        # pending (unread) paths AND both the reconnect budget and the
        # wall-clock budget have headroom. Honouring the wall-clock budget
        # is what lets the FULL reconnect budget actually be used: a single
        # dead path can no longer monopolise the cap before the Desktop
        # paths are re-probed on a fresh session.
        while (
            session_died
            and pending
            and reconnects_used < max_reconnects
            and _budget_remaining() > (reconnect_settle_seconds + 1.0)
        ):
            reconnects_used += 1
            # Re-prioritise: the highest-value conventional Desktop paths get
            # re-probed first on the fresh session, before any (now larger)
            # reconnect budget can be exhausted. Paths that errored as
            # NETWORK_ERROR on a dead session are NOT terminal here — the
            # fresh session gets a real chance to read them.
            pending = _prioritize_conventional_first(pending)
            to_reprobe = len(pending)
            desktop_reprobe = sum(
                1
                for entry in pending
                if _CONVENTIONAL_DESKTOP_RE.match(
                    (entry[0] or "").replace("\\", "/").lower()
                )
            )
            print_info_debug(
                f"[ctf-flags] SMB session looked dead — reconnecting "
                f"({reconnects_used}/{max_reconnects}) after "
                f"{reconnect_settle_seconds:.1f}s settle; re-probing "
                f"{to_reprobe} path(s) on the fresh session "
                f"({desktop_reprobe} Desktop path(s) first, "
                f"{_budget_remaining():.1f}s budget left)"
            )
            # Let the new aiosmb session settle before re-probing — mirrors
            # the walk-race settle fix. Bounded by the wall-clock budget.
            if reconnect_settle_seconds > 0:
                await asyncio.sleep(reconnect_settle_seconds)
            probes_before = len(probe_errors) + len(hits) + len(denied)
            session_died, pending = await _run_session(pending)
            probes_after = len(probe_errors) + len(hits) + len(denied)
            print_info_debug(
                f"[ctf-flags] reconnect {reconnects_used}/{max_reconnects} "
                f"resolved {probes_after - probes_before} path(s) to a "
                f"definitive verdict; {len(pending)} still pending"
            )
        if pending and reconnects_used >= max_reconnects:
            print_info_debug(
                f"[ctf-flags] reconnect budget ({max_reconnects}) exhausted "
                f"with {len(pending)} path(s) still pending"
            )
        elif pending and session_died:
            print_info_debug(
                f"[ctf-flags] wall-clock budget exhausted with {len(pending)} "
                "path(s) still pending"
            )
        # Any path still pending after the loop is marked NETWORK_ERROR so
        # the panel renders something honest (and so `probed=N` reflects it).
        for path, kind, owner in pending:
            probe_errors.append(
                FlagProbeError(
                    path=path, owner=owner or None, kind=kind,
                    outcome=FlagProbeOutcome.NETWORK_ERROR,
                    detail="session unrecoverable",
                    attempts=0,
                    discovered_via=discovered_via,
                )
            )

    _drain_aiosmb_stderr(stderr_buf)
    # Also flush anything that may have been written to the real stderr from
    # within the redirect block (defensive — most aiosmb prints are captured).
    sys.stderr.flush()

    return hits, denied, probe_errors, errors


# ---------------------------------------------------------------------------
# remote_exec fallback strategy
# ---------------------------------------------------------------------------


async def _remote_exec_fallback_strategy(
    *,
    shell,
    config: SMBConfig,
    denied: list[tuple[str, FlagKind, str, str]],
    timeout_seconds: int,
    host: str,
    max_attempts: int = 2,
    backoff_seconds: float = 0.5,
    discovered_via: "FlagDiscoveryStrategy" = None,  # type: ignore[assignment]
) -> tuple[list[FlagHit], ExecMethod | None, list[FlagProbeError], list[str]]:
    """Run ``cmd /c type "<path>"`` for each denied candidate.

    Wraps the cascade in the same retry-with-classification model so the
    operator never sees flapping from this path either.
    """
    if discovered_via is None:
        discovered_via = FlagDiscoveryStrategy.CONVENTIONAL
    hits: list[FlagHit] = []
    errors: list[str] = []
    probe_errors: list[FlagProbeError] = []
    method_used: ExecMethod | None = None

    for share_path, kind, owner, _denied_err in denied:
        win_path = "C:" + share_path.replace("\\C$", "", 1)
        command = f'cmd /c type "{win_path}"'

        host_intel_cache = getattr(shell, 'host_intel_cache', None)
        edr_intel = getattr(shell, 'edr_intel', None)
        workspace_type = getattr(shell, 'type', None)
        adaptive = host_intel_cache is not None
        on_intel = (
            _make_panel_callback(shell, host_intel_cache, workspace_type)
            if adaptive else None
        )

        last_detail = ""
        last_outcome = FlagProbeOutcome.OTHER_ERROR
        attempts_done = 0
        produced_hit = False
        for attempt in range(1, max_attempts + 1):
            attempts_done = attempt
            try:
                result = await execute_with_fallback(
                    config,
                    command,
                    methods=None if adaptive else STDOUT_CASCADE,
                    intel_cache=host_intel_cache,
                    intel=edr_intel,
                    workspace_type=workspace_type,
                    on_intel_resolved=on_intel,
                    timeout=timeout_seconds,
                )
            except AuthError as exc:
                errors.append(f"{win_path}: auth failed ({exc})")
                last_detail = f"auth failed ({exc})"
                last_outcome = FlagProbeOutcome.ACCESS_DENIED
                break  # auth is definitive
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                last_detail = f"cascade error ({exc})"
                last_outcome = _classify_error(exc)
                if _is_retryable(last_outcome) and attempt < max_attempts:
                    print_info_debug(
                        f"[ctf-flags] cascade {win_path} -> {last_outcome.name} "
                        f"retry {attempt}/{max_attempts} ({exc})"
                    )
                    await asyncio.sleep(backoff_seconds * attempt)
                    continue
                errors.append(f"{win_path}: {last_detail}")
                break

            if not result.success:
                detail = "; ".join(
                    f"{f.method}={f.error_kind}: {f.message}" for f in result.errors
                )
                last_detail = detail or "cascade reported failure"
                last_outcome = _classify_error(last_detail)
                if _is_retryable(last_outcome) and attempt < max_attempts:
                    print_info_debug(
                        f"[ctf-flags] cascade {win_path} -> {last_outcome.name} "
                        f"retry {attempt}/{max_attempts} ({last_detail})"
                    )
                    await asyncio.sleep(backoff_seconds * attempt)
                    continue
                errors.append(f"{win_path}: {last_detail}")
                break

            method_used = result.method
            token = _normalise_flag_value(
                result.stdout.encode("utf-8", errors="replace")
            )
            if token is None:
                last_detail = "stdout did not contain a flag"
                last_outcome = FlagProbeOutcome.OTHER_ERROR
                errors.append(f"{win_path}: {last_detail}")
                break
            hits.append(
                FlagHit(
                    host=host,
                    owner_user=owner or None,
                    kind=kind,
                    path=share_path,
                    value=token,
                    flag_hash=_hash_flag(token),
                    captured_at=datetime.now(timezone.utc),
                    method="remote_exec",
                    discovered_via=discovered_via,
                )
            )
            produced_hit = True
            break

        if not produced_hit:
            probe_errors.append(
                FlagProbeError(
                    path=share_path, owner=owner or None, kind=kind,
                    outcome=last_outcome, detail=last_detail or "fallback failed",
                    attempts=attempts_done,
                    discovered_via=discovered_via,
                )
            )

    return hits, method_used, probe_errors, errors


# ---------------------------------------------------------------------------
# Adaptive cascade panel hook
# ---------------------------------------------------------------------------


def _make_panel_callback(shell, host_intel_cache, workspace_type):
    """Return an on_intel_resolved callback that fires the host-intel panel once."""
    def _cb(fp, ranked):
        try:
            from adscan_internal.cli.host_intelligence_panel import (
                build_reason_lines,
                render_host_intelligence_panel,
            )
            shown = getattr(shell, '_host_intel_panels_shown', None)
            if shown is None:
                shown = set()
                shell._host_intel_panels_shown = shown
            if fp.target_ip in shown:
                print_info_debug(f'[host-intel] cache hit for {fp.target_ip}')
                return
            shown.add(fp.target_ip)
            ttl_remaining = None
            if host_intel_cache is not None:
                age = host_intel_cache.cache_age_seconds(fp.target_ip)
                if age is not None:
                    ttl_remaining = max(0, 3600 - age)
            render_host_intelligence_panel(
                console=get_console(),
                fingerprint=fp,
                cascade=ranked,
                reason_lines=build_reason_lines(fp, workspace_type),
                workspace_type=workspace_type,
                cache_ttl_remaining_s=ttl_remaining,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    return _cb


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def collect_ctf_flags(
    *,
    shell,
    domain: str,
    host: str,
    config: SMBConfig,
    candidate_users: Sequence[str] | None = None,
    smb_read_timeout: int = 10,
    remote_exec_timeout: int = 45,
    path_timeout_seconds: float = 10.0,
) -> FlagCollectionResult:
    """Collect HTB/THM flags from ``host``.

    The function never raises to the caller — every failure path is
    captured into :attr:`FlagCollectionResult.errors` /
    :attr:`FlagCollectionResult.probes`.

    Args:
        shell: ADscan shell (used for workspace lookup and the
            native remote_exec cascade fallback). May be ``None`` for
            the byte-read-only path.
        domain: Target domain name (only used for workspace lookup).
        host: Remote host name for hit attribution.
        config: SMB connection config.
        candidate_users: Optional override list of usernames to probe.
            When ``None`` the list is derived from the workspace + a
            small default set (Administrator).
        smb_read_timeout: Legacy alias for ``path_timeout_seconds`` — kept
            for backwards compatibility.
        remote_exec_timeout: Per-file timeout for the cascade fallback.
        path_timeout_seconds: Per-attempt SMB read timeout. Defaults to 10s.

    Returns:
        :class:`FlagCollectionResult` aggregating every hit, every probe
        outcome, and every error encountered.
    """
    from adscan_internal.services.ctf_flag_collector_strategies import (
        powershell_search,
        probe_alternative,
        probe_conventional,
        smb_walk_bounded,
    )

    started_ns = asyncio.get_event_loop().time()
    users, users_source = _candidate_users(
        shell=shell, domain=domain, candidate_users=candidate_users
    )

    # Enrich the candidate list with real C:\Users\ folder names — only folders
    # that actually exist on disk are included, avoiding NOT_FOUND noise for
    # accounts without a profile and catching any user we missed from credentials.
    try:
        smb_users = await asyncio.wait_for(
            _enumerate_users_from_smb(config), timeout=5.0
        )
        if smb_users:
            seen = {u.lower() for u in users}
            added: list[str] = []
            for u in smb_users:
                if u.lower() not in seen:
                    users.append(u)
                    seen.add(u.lower())
                    added.append(u)
            if added:
                users_source = "smb_users_dir"
                print_info_debug(
                    f"[ctf-flags] C:\\Users\\ enumeration added: {added!r}"
                )
    except Exception as _enum_exc:  # noqa: BLE001
        print_info_debug(
            f"[ctf-flags] C:\\Users\\ enumeration failed ({type(_enum_exc).__name__}); "
            "using credential-based candidates only"
        )

    candidates = _candidate_paths(users)

    # Visibility — operator needs to know which users are being probed and
    # where the list came from (especially when zero flags come back).
    print_info_debug(
        f"[ctf-flags] candidate_users resolved: {users!r} (source: {users_source})"
    )
    if [u.lower() for u in users] == ["administrator"]:
        print_info_verbose(
            "[ctf-flags] only \"Administrator\" in candidate_users — flags "
            "owned by other users (e.g. SVC_TGS) won't be probed"
        )

    # Honour the legacy ``smb_read_timeout`` argument when explicitly set.
    effective_timeout = float(path_timeout_seconds)
    if smb_read_timeout and smb_read_timeout != 10:
        effective_timeout = float(smb_read_timeout)

    print_info_debug(
        f"[ctf-flags] probing {len(candidates)} conventional + alternative + "
        f"walk strategies across {len(users)} user(s) on {host} "
        f"(per-path timeout {effective_timeout:.1f}s, hard total cap 25s)"
    )

    errors: list[str] = []
    auth_failed = False

    # Strategy scheduling — reduce the SMB connection storm that makes a
    # reset-happy DC drop sessions. Each strategy opens its OWN connection
    # (one shared session across three concurrent reads corrupted aiosmb
    # state on Forest — see ctf_flag_collector_strategies module docstring),
    # so the lever is HOW MANY run at once, not sharing a connection.
    #
    # Conventional (Desktop — where user.txt / root.txt live) is the
    # highest-value path, so it runs FIRST and ALONE: it gets a clean,
    # uncontended shot at the DC and its built-in reconnect budget is not
    # competing with the walk / alternative connections. Only then do the
    # two lower-value strategies (alternative byte-read + recursive walk)
    # run together (2 sessions, not 4+). A single 25s deadline is shared
    # across both phases (per spec).
    started_strategies = asyncio.get_event_loop().time()

    def _remaining_budget() -> float:
        elapsed = asyncio.get_event_loop().time() - started_strategies
        return max(0.0, 25.0 - elapsed)

    def _outcome(task, pending_set):
        if task in pending_set or task.cancelled():
            return None
        exc = task.exception()
        if exc is not None:
            telemetry.capture_exception(exc)
            errors.append(f"{task.get_name()}: {exc}")
            return None
        return task.result()

    # Phase 1 — conventional alone (Desktop paths, with reconnect budget).
    conv_task = asyncio.create_task(
        probe_conventional(
            config=config,
            candidates=candidates,
            host=host,
            path_timeout_seconds=effective_timeout,
            total_budget_seconds=max(1.0, _remaining_budget()),
        ),
        name="ctf_flags:conventional",
    )
    conv_done, conv_pending = await asyncio.wait(
        [conv_task], timeout=_remaining_budget(), return_when=asyncio.ALL_COMPLETED
    )
    for t in conv_pending:
        t.cancel()
        errors.append(f"strategy {t.get_name()} cancelled at 25s timeout")
    conv_out = _outcome(conv_task, conv_pending)

    # Phase 2 — alternative byte-read + recursive walk together (2 sessions).
    # Skipped entirely if the deadline is already spent.
    alt_out = None
    walk_out = None
    budget_left = _remaining_budget()
    if budget_left > 0.5:
        alt_task = asyncio.create_task(
            probe_alternative(
                config=config,
                users=users,
                host=host,
                path_timeout_seconds=effective_timeout,
                total_budget_seconds=max(1.0, budget_left),
            ),
            name="ctf_flags:alternative",
        )
        walk_task = asyncio.create_task(
            smb_walk_bounded(
                config=config,
                host=host,
                path_timeout_seconds=effective_timeout,
            ),
            name="ctf_flags:walk",
        )
        phase2_tasks = [alt_task, walk_task]
        _done2, pending2 = await asyncio.wait(
            phase2_tasks, timeout=budget_left, return_when=asyncio.ALL_COMPLETED
        )
        for t in pending2:
            t.cancel()
            errors.append(f"strategy {t.get_name()} cancelled at 25s timeout")
        alt_out = _outcome(alt_task, pending2)
        walk_out = _outcome(walk_task, pending2)
    else:
        errors.append(
            "strategies ctf_flags:alternative / ctf_flags:walk skipped "
            "(25s budget spent by conventional phase)"
        )

    hits_conv: list[FlagHit] = list(conv_out.hits) if conv_out else []
    hits_alt: list[FlagHit] = list(alt_out.hits) if alt_out else []
    hits_walk: list[FlagHit] = list(walk_out.hits) if walk_out else []

    probe_errors: list[FlagProbeError] = []
    if conv_out:
        probe_errors.extend(conv_out.probe_errors)
        errors.extend(conv_out.errors)
        if any("smb auth failed" in e for e in conv_out.errors):
            auth_failed = True
    if alt_out:
        probe_errors.extend(alt_out.probe_errors)
        errors.extend(alt_out.errors)
    if walk_out:
        probe_errors.extend(walk_out.probe_errors)
        errors.extend(walk_out.errors)

    # remote_exec fallback only for ACCESS_DENIED cases on the conventional
    # strategy. Re-derive denied list from probe_errors flagged
    # CONVENTIONAL + ACCESS_DENIED.
    fallback_used = False
    fallback_method: ExecMethod | None = None
    hits_fallback: list[FlagHit] = []
    fallback_probe_errors: list[FlagProbeError] = []
    denied_conv = [
        (pe.path, pe.kind, pe.owner or "", pe.detail)
        for pe in probe_errors
        if pe.discovered_via == FlagDiscoveryStrategy.CONVENTIONAL
        and pe.outcome == FlagProbeOutcome.ACCESS_DENIED
    ]
    if denied_conv and shell is not None:
        already_hit = {h.path for h in (*hits_conv, *hits_alt, *hits_walk)}
        denied_to_try = [d for d in denied_conv if d[0] not in already_hit]
        if denied_to_try:
            print_info_debug(
                f"[ctf-flags] {len(denied_to_try)} path(s) returned "
                "ACCESS_DENIED — falling back to remote_exec cascade"
            )
            fallback_used = True
            try:
                (
                    hits_fallback,
                    fallback_method,
                    fallback_probe_errors,
                    fb_errors,
                ) = await _remote_exec_fallback_strategy(
                    shell=shell,
                    config=config,
                    denied=denied_to_try,
                    timeout_seconds=remote_exec_timeout,
                    host=host,
                    discovered_via=FlagDiscoveryStrategy.CONVENTIONAL,
                )
                errors.extend(fb_errors)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                errors.append(f"remote_exec fallback raised: {exc}")

    # PowerShell recursive search — runs after all SMB strategies when at
    # least one expected flag kind (user / root / system) is still missing.
    # One command covers all of C:\Users\, then falls back to C:\ if needed,
    # catching non-standard locations like C:\flags\user.txt without needing
    # to know usernames in advance.
    hits_ps: list[FlagHit] = []
    found_kinds = {h.kind for h in (*hits_conv, *hits_alt, *hits_walk, *hits_fallback)}
    # CTF boxes always have exactly 2 flags: user + one privileged flag.
    # HTB uses "root", THM uses "system" — never both.  Once user AND any
    # privileged flag are found the set is complete; don't search for the
    # provider's alternative name.
    _found_user = "user" in found_kinds
    _found_privileged = bool(found_kinds & {"root", "system"})
    if _found_user and _found_privileged:
        missing_kinds: set[str] = set()
    else:
        missing_kinds = set()
        if not _found_user:
            missing_kinds.add("user")
        if not _found_privileged:
            missing_kinds |= {"root", "system"}
    if missing_kinds and shell is not None:
        print_info_debug(
            f"[ctf-flags] ps_search triggered: missing kinds {sorted(missing_kinds)}"
        )
        try:
            # Per-method budget 15s: SMB-exec methods fail fast on a
            # reset-happy DC, leaving room for the cascade to fall through
            # to WinRM (PSRP / 5985, distinct transport) within the outer
            # cap. Bounded last-resort — runs only after every SMB
            # byte-read strategy missed.
            ps_out = await asyncio.wait_for(
                powershell_search(
                    config=config,
                    shell=shell,
                    host=host,
                    timeout_seconds=15,
                ),
                timeout=50.0,
            )
            hits_ps = list(ps_out.hits)
            probe_errors.extend(ps_out.probe_errors)
            errors.extend(ps_out.errors)
        except asyncio.TimeoutError:
            errors.append("ps_search cancelled at 50s timeout")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            errors.append(f"ps_search raised: {exc}")

    # Reduce: per (kind, owner) pick the best hit. Conventional wins over
    # alternative wins over smb_walk; smb_read wins over remote_exec.
    strategy_rank = {
        FlagDiscoveryStrategy.CONVENTIONAL: 0,
        FlagDiscoveryStrategy.ALTERNATIVE: 1,
        FlagDiscoveryStrategy.SMB_WALK: 2,
        FlagDiscoveryStrategy.POWERSHELL_SEARCH: 3,
    }
    method_rank = {"smb_read": 0, "remote_exec": 1}

    by_key: dict[tuple[FlagKind, str | None], FlagHit] = {}
    for h in (*hits_conv, *hits_alt, *hits_walk, *hits_fallback, *hits_ps):
        key = (h.kind, h.owner_user)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = h
            continue
        # Prefer lower strategy rank, then lower method rank.
        new_score = (
            strategy_rank.get(h.discovered_via, 99),
            method_rank.get(h.method, 99),
        )
        old_score = (
            strategy_rank.get(existing.discovered_via, 99),
            method_rank.get(existing.method, 99),
        )
        if new_score < old_score:
            by_key[key] = h
    # Re-classify discovered_via from the path itself — the strategy that
    # surfaced a hit first is not the same thing as the location class.
    # See _classify_discovery for the rationale.
    final_hits = tuple(
        replace(h, discovered_via=_classify_discovery(h.path))
        for h in by_key.values()
    )

    # Drop probe_errors for paths that ultimately produced a hit.
    hit_paths = {h.path for h in final_hits}
    final_probe_errors = tuple(
        pe for pe in (*probe_errors, *fallback_probe_errors)
        if pe.path not in hit_paths
    )

    walk_stats: WalkStats | None = None
    if walk_out and walk_out.walk_stats is not None:
        ws = walk_out.walk_stats
        per_root_raw = ws.get("per_root", []) or []
        per_root = tuple(
            WalkRootStats(
                root=r.get("root", ""),
                files_scanned=int(r.get("files_scanned", 0) or 0),
                dirs_traversed=int(r.get("dirs_traversed", 0) or 0),
                dirs_excluded=int(r.get("dirs_excluded", 0) or 0),
                candidates_evaluated=int(r.get("candidates_evaluated", 0) or 0),
                elapsed_ms=int(r.get("elapsed_ms", 0) or 0),
                error=r.get("error"),
            )
            for r in per_root_raw
        )
        walk_stats = WalkStats(
            files_scanned=ws.get("files_scanned", 0),
            dirs_traversed=ws.get("dirs_traversed", 0),
            dirs_excluded=ws.get("dirs_excluded", 0),
            candidates_evaluated=ws.get("candidates_evaluated", 0),
            elapsed_ms=ws.get("elapsed_ms", 0),
            hit_max_entries=ws.get("hit_max_entries", False),
            per_root=per_root,
        )

    elapsed_ms = int((asyncio.get_event_loop().time() - started_ns) * 1000)

    # Telemetry — useful for tuning the catalog over the next 6 months.
    try:
        breakdown: dict[str, int] = {}
        for h in final_hits:
            key = h.discovered_via.value if hasattr(h.discovered_via, "value") else str(h.discovered_via)
            breakdown[key] = breakdown.get(key, 0) + 1
        telemetry.capture(
            "ctf_flags.collection",
            {
                "host": host,
                "domain": domain,
                "kinds_found": sorted({h.kind for h in final_hits}),
                "discovery_breakdown": breakdown,
                "walk_files_scanned": walk_stats.files_scanned if walk_stats else 0,
                "walk_hit_max": walk_stats.hit_max_entries if walk_stats else False,
                "elapsed_ms": elapsed_ms,
                "auth_failed": auth_failed,
                "fallback_used": fallback_used,
            },
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    result = FlagCollectionResult(
        hits=final_hits,
        elapsed_ms=elapsed_ms,
        primary_strategy="smb_read",
        fallback_used=fallback_used,
        fallback_method=fallback_method,
        errors=tuple(errors),
        probes=final_probe_errors,
        walk_stats=walk_stats,
    )

    # Visibility-only diagnostic — fires only when zero flags came back.
    if len(result.hits) == 0:
        aiosmb_stderr_lines: list[str] = []
        for out in (conv_out, alt_out, walk_out):
            if out is None:
                continue
            lines = getattr(out, "aiosmb_stderr_lines", None) or []
            aiosmb_stderr_lines.extend(lines)
        _emit_diagnostic_summary(
            result=result,
            candidate_users=users,
            candidate_users_source=users_source,
            aiosmb_stderr_lines=aiosmb_stderr_lines,
        )

    return result


# ---------------------------------------------------------------------------
# Diagnostic summary (visibility-only)
# ---------------------------------------------------------------------------


def _summarize_outcomes(
    probes: Sequence[FlagProbeError], strategy: FlagDiscoveryStrategy
) -> tuple[int, dict[str, int]]:
    """Aggregate probe outcomes for one strategy.

    Args:
        probes: All probe errors recorded across the run.
        strategy: Discovery strategy to filter on.

    Returns:
        Tuple ``(probed_count, outcome_counts)`` where ``outcome_counts``
        maps outcome name (e.g. ``"NOT_FOUND"``) to a count. Pure logic —
        unit-tested.
    """
    counts: dict[str, int] = {}
    probed = 0
    for pe in probes:
        if pe.discovered_via != strategy:
            continue
        probed += 1
        counts[pe.outcome.name] = counts.get(pe.outcome.name, 0) + 1
    return probed, counts


def _pick_diagnostic_hint(result: "FlagCollectionResult") -> str:
    """Pick the most actionable hint for a zero-hit run.

    Pure function — covers the four dominant failure modes seen on
    HTB / customer boxes. Order is by specificity, most concrete first.
    Unit-tested.
    """
    probes = result.probes
    walk = result.walk_stats

    access_denied = sum(
        1 for p in probes if p.outcome == FlagProbeOutcome.ACCESS_DENIED
    )
    not_found = sum(
        1 for p in probes if p.outcome == FlagProbeOutcome.NOT_FOUND
    )
    network = sum(
        1
        for p in probes
        if p.outcome
        in (FlagProbeOutcome.NETWORK_ERROR, FlagProbeOutcome.TIMEOUT)
    )

    if walk is not None and walk.files_scanned == 0:
        return (
            "SMB walk did not start (auth or transport failure on walk "
            "session) — verify SMB reachability and credential rights"
        )
    if network > 0 and (access_denied + not_found) == 0:
        return (
            "transport-level failures dominate — likely SMBv1 negotiation "
            "or signing mismatch (common on HTB Server 2008 boxes)"
        )
    if access_denied > 0 and access_denied >= not_found:
        return (
            "credential lacks read rights on Desktop — try a different "
            "user (e.g. via `--candidate-users`) or escalate first"
        )
    if not_found > 0 and access_denied == 0:
        return (
            "candidate_users may be wrong — every probe returned NOT_FOUND. "
            "Pass the actual flag owner via `--candidate-users <name>`"
        )
    return (
        "no dominant failure mode — try `get_flags <domain> <user> <pass>` "
        "with explicit candidate users, or check SMB reachability"
    )


_LAVA = "[bold red]"
_MUTED = "[dim]"
_RESET = "[/]"


def _emit_diagnostic_summary(
    *,
    result: "FlagCollectionResult",
    candidate_users: Sequence[str],
    candidate_users_source: str,
    aiosmb_stderr_lines: Sequence[str],
) -> None:
    """Emit a multi-line INFO block explaining a zero-flag run.

    Visibility-only — never fires when ``result.hits`` is non-empty.
    Output mirrors :func:`print_info` so it is visible without
    ``--verbose``. Format is two-column aligned with a 20-char label.
    """
    label_w = 20

    def _row(label: str, value: str) -> str:
        return f"  {label.ljust(label_w)} {value}"

    print_info("\\[ctf-flags] No flags captured. Diagnostic breakdown:")
    print_info(_row("candidate_users", f"{list(candidate_users)!r} (source: {candidate_users_source})"))

    for strat, label in (
        (FlagDiscoveryStrategy.CONVENTIONAL, "conventional"),
        (FlagDiscoveryStrategy.ALTERNATIVE, "alternative"),
        (FlagDiscoveryStrategy.SMB_WALK, "smb_walk"),
    ):
        probed, counts = _summarize_outcomes(result.probes, strat)
        if strat is FlagDiscoveryStrategy.SMB_WALK:
            ws = result.walk_stats
            if ws is None:
                print_info(_row(label, "no walk stats (strategy did not run)"))
            else:
                print_info(
                    _row(
                        label,
                        f"files_scanned={ws.files_scanned}  "
                        f"candidates={ws.candidates_evaluated}  "
                        f"probed={probed}  hits=0",
                    )
                )
                for r in ws.per_root:
                    if r.error:
                        absent = (
                            "object_name_not_found" in r.error.lower()
                            or "status_object_path_not_found" in r.error.lower()
                            or "0xc0000034" in r.error.lower()
                            or "0xc000003a" in r.error.lower()
                        )
                        # Expected absences (inetpub/xampp on a non-IIS box)
                        # render muted; real failures (C$, Users) render lava.
                        is_critical_root = any(
                            t in r.root.lower() for t in ("\\c$\\users", "\\c$\\")
                        ) and not any(
                            t in r.root.lower() for t in ("\\inetpub", "\\xampp")
                        )
                        style = _LAVA if (is_critical_root and not absent) else _MUTED
                        print_info(
                            _row(
                                "",
                                f"{style}{r.root:<14}{_RESET} -> ERROR: {r.error}",
                            )
                        )
                    else:
                        print_info(
                            _row(
                                "",
                                f"{r.root:<14} -> {r.files_scanned} files, "
                                f"{r.dirs_traversed} dirs traversed, "
                                f"candidates={r.candidates_evaluated}",
                            )
                        )
        else:
            counts_str = (
                "{" + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) + "}"
                if counts else "{}"
            )
            print_info(
                _row(label, f"probed={probed}  hits=0  {counts_str}")
            )

    if aiosmb_stderr_lines:
        print_info(_row("aiosmb stderr", f"{len(aiosmb_stderr_lines)} line(s) captured"))

    print_info(_row("Hint", _pick_diagnostic_hint(result)))

    if aiosmb_stderr_lines:
        print_info(
            f"\\[ctf-flags] aiosmb diagnostic stderr ({len(aiosmb_stderr_lines)} lines):"
        )
        for line in aiosmb_stderr_lines:
            print_info(f"  {line}")
        print_info(
            "\\[ctf-flags] These typically indicate transport-level failures "
            "(SMBv1 negotiation, signing, session corruption). For HTB "
            "Server 2008 boxes (e.g. Active), this is consistent with "
            "SMBv1 servers that aiosmb cannot negotiate cleanly. Workaround: "
            "use the command-execution fallback explicitly."
        )


__all__ = [
    "FlagHit",
    "FlagProbeError",
    "FlagProbeOutcome",
    "FlagDiscoveryStrategy",
    "FlagCollectionResult",
    "FlagKind",
    "FlagMethod",
    "WalkRootStats",
    "WalkStats",
    "collect_ctf_flags",
]
