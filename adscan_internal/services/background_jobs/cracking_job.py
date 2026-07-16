"""Cracking as a background job (auto-crack captured hashes off the scan flow).

Runs against ANY supported hashcat mode — NetNTLMv1/v2 (5500/5600), Kerberoast
(13100 + AES 19600/19700) and AS-REP roast (18200 + AES 19800/19900) — walking
the wordlist tiers in order and running hashcat non-interactively per tier. On a
match: ``shell.add_credential`` for every cracked principal + a 'cracked'
JobResult; on exhaustion: an 'uncracked' JobResult. NEVER prints/prompts.

The runtime keys on an explicit hashcat ``mode`` string (not the old NetNTLM-only
``ntlm_version`` assumption). ``ntlm_version`` is still accepted as a
backward-compatible way to derive the NetNTLM mode for existing callers.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import threading
import time
from typing import Any, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.background_jobs.results_bus import (
    JobResult,
    JobResultSink,
)
from adscan_internal.services.cracking_wordlist_policy import EffortTier

# NetNTLM hashcat modes (fixed per protocol version, unlike the etype-dependent
# Kerberoast/AS-REP modes): 5500 = NetNTLMv1, 5600 = NetNTLMv2. Mirrors
# adscan_internal.cli.cracking's _HASHCAT_MODE_DESCRIPTIONS mapping.
_NTLM_V1_MODE = "5500"
_NTLM_V2_MODE = "5600"

# hashcat modes grouped by human-readable hash family, for the JobResult labels.
# Roast modes span RC4 + the two AES etypes (same $krb5*$ shape).
_KERBEROAST_MODES = {"13100", "19600", "19700"}
_ASREP_MODES = {"18200", "19800", "19900"}


def _hashcat_mode_for_version(version: str) -> str:
    """Return the fixed hashcat mode for a captured NetNTLM version."""
    normalized = str(version or "").strip().lower()
    if normalized in {"v1", "ntlmv1", "netntlmv1"}:
        return _NTLM_V1_MODE
    return _NTLM_V2_MODE


def _resolve_runtime_mode(mode: Optional[str], ntlm_version: str) -> str:
    """Resolve the concrete hashcat mode string the runtime should crack under.

    An explicit ``mode`` wins (any hashcat mode — roast or NetNTLM); when it is
    absent the mode is derived from the legacy ``ntlm_version`` so existing
    NetNTLM callers keep working byte-for-byte.
    """
    if mode is not None and str(mode).strip():
        return str(mode).strip()
    return _hashcat_mode_for_version(ntlm_version)


def _mode_label(mode: str) -> str:
    """Human-readable hash-family label for a hashcat mode, for JobResults."""
    m = str(mode or "").strip()
    if m == _NTLM_V1_MODE:
        return "NetNTLMv1"
    if m == _NTLM_V2_MODE:
        return "NetNTLMv2"
    if m in _KERBEROAST_MODES:
        return "Kerberoast"
    if m in _ASREP_MODES:
        return "AS-REP"
    return f"mode {m}" if m else "hash"


# The non-interactive equivalent of hashcat's interactive "s" status key: emit a
# machine-readable JSON status object every N seconds so a running crack's
# progress / ETA can be surfaced without the (blocking) interactive prompt.
_STATUS_TIMER_SECONDS = "5"

# A status callback the runtime supplies so a crack pass can hand back the last
# parsed hashcat status (progress / ETA) for the in-progress harvest row.
StatusSink = Callable[[dict], None]

# A callback the runtime supplies so a crack pass can report whether it currently
# HOLDS the single-instance hashcat slot: ``True`` the moment it acquires the
# slot (hashcat is running), ``False`` on release. Lets ``snapshot()`` tell a
# crack that is actually running hashcat apart from one that is alive but WAITING
# behind another crack for the slot (queued) — WITHOUT touching the slot
# mechanics; it only OBSERVES this runtime's own hold.
SlotStateSink = Callable[[bool], None]


# ── background-crack responsiveness via resource ISOLATION ────────────────────
#
# A BACKGROUND crack runs on a worker thread WHILE the operator keeps driving the
# interactive REPL. hashcat at normal OS priority on ALL OpenCL devices (the GPU
# AND every CPU core) saturates the CPU, so prompt_toolkit's input loop is starved
# and keystrokes lag/drop. The fix is RESOURCE ISOLATION — physically leaving the
# input-bound REPL something to run on — NOT throttling the crack's speed:
#   * ``-D 2``           — GPU-only device selection when a usable GPU is present,
#     so EVERY CPU core stays free for the REPL. On a GPU host this alone keeps the
#     REPL responsive regardless of the crack's workload, so the crack runs at FULL
#     GPU speed. Omitted on CPU-only hosts (hashcat must use the CPU there; the core
#     reservation below carries the guarantee).
#   * ``taskset -c 0-N`` — on a GPU-less host, PIN hashcat to all-but-N CPU cores so
#     N cores are PHYSICALLY free for the REPL. This is the SOLE background-crack
#     responsiveness mechanism on GPU-less hosts: the OS runs the input-bound REPL
#     on the reserved cores hashcat cannot touch, so the crack runs at (near-)full
#     speed on the rest. The reservation SCALES with host size (see
#     ``_repl_reserved_cores``) so a tiny VM is never over-reserved and a large host
#     never starves the REPL. It is the hard guarantee for the CPU-only hosts that
#     are the majority of ADscan environments (VMs / containers without GPU
#     passthrough).
#   * ``nice -n 19``     — cheap scheduling insurance: lowest OS priority (an
#     unprivileged user can RAISE its own niceness) so the interactive foreground
#     wins any CPU tie. A soft lever ON TOP of the isolation above, not a throttle.
#
# Deliberately NO ``-w`` workload profile is forced: hashcat runs at its DEFAULT
# (``-w 2``, balanced). The old ``-w 1`` "Low" throttle cost ~15% crack speed to buy
# responsiveness the isolation above ALREADY provides for free (GPU-free CPU / a
# reserved-core REPL), so it was redundant and is dropped — full speed AND responsive.
#
# CRITICAL: isolation is scoped to BACKGROUND cracks ONLY. A FOREGROUND/blocking
# crack (the operator is watching, the REPL is blocked, nothing concurrent to
# protect) runs at FULL speed — no nice, no device/core restriction — because
# faster completion is strictly better when there is no interactivity to starve.
# The separate interactive foreground path (cli/cracking.py::execute_cracking)
# already runs full-speed and is deliberately left untouched.
_BACKGROUND_NICENESS = "19"
# hashcat --opencl-device-types numbering: 1=CPU, 2=GPU, 3=FPGA. The benchmark
# (services/cracking_benchmark) already runs ``hashcat -b -D 2`` for its GPU
# measurement, so ``-D 2`` selecting a GPU-type device is proven on this build.
_GPU_DEVICE_TYPE = "2"
# Cores physically reserved for the interactive REPL when a background crack (or
# the benchmark warm-up) must run on the CPU (no usable GPU). The count SCALES with
# host size (``_repl_reserved_cores``): 1 core on small hosts (≤ the threshold) so a
# tiny VM keeps most of its cores for the crack, 2 on larger hosts where sparing an
# extra core costs the (already deprioritised) crack nothing but keeps a busy REPL
# smooth. Below a hard floor no reservation is applied at all (pinning would starve
# the crack more than the REPL lag it would prevent).
_REPL_RESERVED_CORES_SMALL = 1
_REPL_RESERVED_CORES_LARGE = 2
# At/under this core count a host is "small" and reserves only 1 core.
_SMALL_HOST_CORE_THRESHOLD = 8


def _repl_reserved_cores(cpu_count: int) -> int:
    """Cores to reserve for the REPL, scaled by host size.

    Small hosts (``cpu_count <= _SMALL_HOST_CORE_THRESHOLD``) reserve a single
    core so a tiny VM keeps the bulk of its cores for the crack; larger hosts
    reserve two, which a busy REPL benefits from and an already-deprioritised
    background crack never misses.
    """
    if cpu_count <= _SMALL_HOST_CORE_THRESHOLD:
        return _REPL_RESERVED_CORES_SMALL
    return _REPL_RESERVED_CORES_LARGE

# Crack subprocess bounding. A crack must run until it cracks the hash, exhausts
# its wordlist x rules keyspace, or is stopped — it must NEVER be killed while it
# is legitimately working. The old fixed 300s cap aborted a thorough-tier crack
# (combined_audit_base x a 10k-rule file, ~15-25 min on a mid-range GPU) at ~22%,
# so the hash never cracked. Instead of an elapsed cap (fixed OR benchmark-
# derived — both kill a legit crack that runs slower than expected, e.g. under
# GPU thermal throttling), the crack is bounded by an OUTPUT-SILENCE watchdog:
# with ``--status-json --status-timer`` a healthy hashcat emits a status line
# every few seconds REGARDLESS of progress speed, so "no output at all for the
# silence window" reliably means wedged while a steadily-progressing multi-hour
# crack is never touched. The window has generous margin over the 5s status
# cadence and the initial autotune gap ("Starting autotune. Please be patient…").
_CRACK_SILENCE_TIMEOUT_SECONDS = 120.0
# The ``--show`` completion pass is a quick potfile lookup, not a crack, so a
# short overall timeout is correct there.
_SHOW_PASS_TIMEOUT_SECONDS = 300


def _nice_prefix() -> list[str]:
    """Return a ``nice -n 19`` argv prefix, or ``[]`` when ``nice`` is absent.

    Degrades gracefully: if ``nice`` is not on PATH in the runtime image the
    crack still launches (just without the low-priority hint). Never raises.
    """
    try:
        if shutil.which("nice"):
            return ["nice", "-n", _BACKGROUND_NICENESS]
    except Exception as exc:  # noqa: BLE001 — the priority hint is best-effort
        telemetry.capture_exception(exc)
    return []


def _gpu_only_device_args() -> list[str]:
    """Return ``["-D", "2"]`` when a usable GPU is KNOWN present, else ``[]``.

    Reuses the benchmark's already-collected device info
    (:func:`cracking_benchmark.detect_gpu_present`) — it runs NO new
    ``hashcat -I`` probe. Best-effort and conservative: ``-D 2`` is added ONLY on
    a definitive GPU signal (the benchmark proved ``hashcat -b -D 2`` selects a
    working device on this machine), so it can never leave the crack with no
    device to run on. When GPU presence is UNKNOWN (no benchmark yet) or the host
    is CPU-only, ``-D`` is omitted so hashcat still runs on the CPU — the
    ``taskset`` core reservation + ``nice`` keep it responsive there.
    """
    try:
        from adscan_internal.services.cracking_benchmark import (  # noqa: PLC0415
            detect_gpu_present,
        )

        if detect_gpu_present() is True:
            return ["-D", _GPU_DEVICE_TYPE]
    except Exception as exc:  # noqa: BLE001 — GPU detection is best-effort
        telemetry.capture_exception(exc)
    return []


def _cpu_reservation_prefix() -> list[str]:
    """Return a ``taskset -c 0-<N-reserved-1>`` argv prefix reserving the top CPU
    cores for the interactive REPL, or ``[]`` when it should not / cannot apply.

    This is the SOLE background-crack responsiveness mechanism on a GPU-less host:
    hashcat is PINNED to all-but-``_repl_reserved_cores(N)`` cores, leaving those
    cores physically free so the OS runs the input-bound REPL there while the crack
    saturates the rest at (near-)full speed. It matters most on the CPU-only hosts
    that are the majority of ADscan environments (VMs / containers with no GPU
    passthrough), and it replaces the old ``-w 1`` throttle — isolation gives
    responsiveness AND full crack speed, where the throttle traded ~15% speed away.

    Applies ONLY when NO usable GPU is present (``detect_gpu_present()`` is not
    ``True`` — CPU-only OR unknown). With a GPU the crack runs ``-D 2`` GPU-only
    and leaves the CPU free already, so pinning cores is pointless there. The
    reservation count SCALES with host size via :func:`_repl_reserved_cores` (1
    core on small hosts, 2 on larger). Degrades gracefully to ``[]`` (``nice``
    remains the soft lever) when ``taskset`` is absent from PATH, when
    ``os.cpu_count()`` is unknown, or when the host is too small to spare the
    reservation and still leave hashcat at least two cores (never over-reserve a
    tiny VM). Never raises — a best-effort responsiveness guarantee must not break
    a crack.
    """
    try:
        from adscan_internal.services.cracking_benchmark import (  # noqa: PLC0415
            detect_gpu_present,
        )

        if detect_gpu_present() is True:
            return []  # a GPU frees the CPU via -D 2; no core reservation needed.
        if not shutil.which("taskset"):
            return []
        cpu_count = os.cpu_count() or 0
        reserved = _repl_reserved_cores(cpu_count)
        # Never over-reserve a tiny VM: only pin when hashcat still keeps at least
        # two cores after the reservation (below that, pinning starves the crack
        # more than the REPL lag it would prevent; nice alone carries it).
        if cpu_count - reserved < 2:
            return []
        # Reserve the top ``reserved`` cores: pin to cores 0..(N-reserved-1).
        last_usable_core = cpu_count - reserved - 1
        return ["taskset", "-c", f"0-{last_usable_core}"]
    except Exception as exc:  # noqa: BLE001 — core reservation is best-effort
        telemetry.capture_exception(exc)
    return []


def _method_label(wordlist: str, rules_path: Optional[str]) -> str:
    """Human-readable method for a crack tier: wordlist basename (+ rule name).

    Returns e.g. ``"combined_audit_base.txt"`` for a bare wordlist tier, or
    ``"combined_audit_base.txt + best64"`` when a rules file is applied (the
    rule's own extension is dropped for compactness). Empty when no wordlist.
    """
    base = os.path.basename(str(wordlist or "")).strip()
    if not base:
        return ""
    rule = os.path.basename(str(rules_path or "")).strip()
    if rule:
        rule_name = os.path.splitext(rule)[0] or rule
        return f"{base} + {rule_name}"
    return base


def parse_hashcat_status_json(line: str) -> "Optional[dict[str, Any]]":
    """Parse one hashcat ``--status-json`` line into ``{progress_pct, eta_seconds}``.

    hashcat with ``--status-json`` emits a JSON object per ``--status-timer``
    tick carrying ``progress`` (a ``[current, total]`` keyspace position) and
    ``estimated_stop`` (a Unix epoch). Returns
    ``{"progress_pct": float|None, "eta_seconds": int|None}`` or ``None`` when
    the line is not a parseable status object or carries neither field.
    Best-effort: never raises — a malformed line yields ``None`` so the caller
    falls back to a plain ``cracking …`` display.
    """
    text = str(line or "").strip()
    if not text or text[0] != "{":
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    progress_pct: Optional[float] = None
    prog = data.get("progress")
    if isinstance(prog, (list, tuple)) and len(prog) == 2:
        try:
            current = float(prog[0])
            total = float(prog[1])
            if total > 0:
                progress_pct = max(0.0, min(100.0, 100.0 * current / total))
        except (TypeError, ValueError):
            progress_pct = None
    eta_seconds: Optional[int] = None
    stop = data.get("estimated_stop")
    if isinstance(stop, (int, float)) and not isinstance(stop, bool):
        eta_seconds = max(0, int(stop) - int(time.time()))
    if progress_pct is None and eta_seconds is None:
        return None
    return {"progress_pct": progress_pct, "eta_seconds": eta_seconds}


def format_progress_pct(progress_pct: "Optional[float]") -> str:
    """Format a 0-100 progress fraction as ``"33%"`` (``""`` when unknown)."""
    if not isinstance(progress_pct, (int, float)):
        return ""
    return f"{int(progress_pct)}%"


def format_eta_seconds(eta_seconds: "Optional[int]") -> str:
    """Format a remaining-seconds estimate as ``"~4m left"`` (``""`` when unknown)."""
    if not isinstance(eta_seconds, (int, float)):
        return ""
    seconds = int(eta_seconds)
    if seconds < 0:
        return ""
    if seconds < 60:
        return f"~{seconds}s left"
    minutes = seconds // 60
    if minutes < 60:
        return f"~{minutes}m left"
    hours = minutes // 60
    return f"~{hours}h {minutes % 60}m left"


def _make_status_line_handler(status_sink: StatusSink) -> Callable[[str], None]:
    """Return a per-line handler that parses hashcat ``--status-json`` LIVE.

    Wired into ``shell.run_command(..., on_line=...)`` so each status line is
    parsed the moment hashcat emits it (every ``--status-timer`` tick), handing
    a valid ``{progress_pct, eta_seconds}`` to ``status_sink`` — this is what
    gives the in-progress harvest row hashcat's REAL live ETA/progress instead
    of only a post-completion value. The handler NEVER prints (it runs on the
    crack's incremental reader, potentially a background thread) and never
    raises — a malformed / non-status line yields no update rather than breaking
    the crack.
    """

    def _on_line(line: str) -> None:
        try:
            parsed = parse_hashcat_status_json(line)
            if parsed is not None:
                status_sink(parsed)
        except Exception as exc:  # noqa: BLE001 — live status parsing is best-effort
            telemetry.capture_exception(exc)

    return _on_line


def _emit_last_status(crack_result: Any, status_sink: StatusSink) -> None:
    """Parse the crack's captured stdout for status-json lines; emit the last.

    A post-completion backstop for the LIVE streaming handler
    (:func:`_make_status_line_handler`): if the incremental reader was
    unavailable (e.g. a shell whose ``run_command`` does not accept ``on_line``)
    the accumulated stdout is re-parsed here so the last known status is still
    surfaced. Best-effort: any parse failure is swallowed so a crack never
    breaks on unparseable status output.
    """
    try:
        text = getattr(crack_result, "stdout", "") or ""
        last: "Optional[dict[str, Any]]" = None
        for line in text.splitlines():
            parsed = parse_hashcat_status_json(line)
            if parsed is not None:
                last = parsed
        if last is not None:
            status_sink(last)
    except Exception as exc:  # noqa: BLE001 — status parsing is best-effort
        telemetry.capture_exception(exc)


def _run_hashcat_tier(
    shell: Any, hash_file: str, wordlist: str, mode: str,
    *, rules_path: Optional[str] = None, status_sink: Optional[StatusSink] = None,
    slot_state_sink: Optional[SlotStateSink] = None, background: bool = False,
) -> dict:
    """Run one hashcat pass against ``hash_file`` with ``wordlist`` under ``mode``.

    ``mode`` is the hashcat mode string passed straight to ``-m`` (5500/5600 for
    NetNTLM, 13100/18200 and their AES variants for roast). Returns a
    ``{username: password}`` mapping of matches (empty on no match or any
    failure). Never prints/prompts — this runs inside a background thread.

    Note on the real API: ``HashcatCrackingService`` does NOT execute hashcat
    itself (it has no ``crack(...)`` method) — it only post-processes an
    already-produced ``hashcat --show`` output file via
    ``extract_creds_from_hash(file_path) -> HashcatCrackingResult`` (a
    ``.credentials`` mapping). So this helper runs hashcat directly via
    ``shell.run_command`` (the SAME ``-m <mode> --username ... --show
    --outfile-format 2`` shape used by the interactive path in
    ``cli/cracking.py::execute_cracking``) and then hands the ``--show`` output
    to the service's parser — reusing the parsing logic without reimplementing
    it, and without pulling in the interactive path's Rich panels/prompts.

    ``rules_path``, when set, is passed as hashcat ``-r <rules_path>`` — the
    same convention as the interactive path's ``select_rules_for_crack`` /
    ``execute_cracking`` (``cli/cracking.py``). Effort-tier callers
    (``cracking_wordlist_policy.resolve_effort``) resolve a rule file for the
    ``balanced``/``thorough`` tiers; the legacy bare-wordlist tiers never set
    this.

    ``background`` gates the isolation levers. When ``True`` (a BACKGROUND crack
    running on a worker thread WHILE the operator drives the REPL) the crack is
    launched isolated — GPU-only ``-D 2`` (or a ``taskset`` core reservation on a
    GPU-less host) + ``nice`` — so it never starves the interactive input loop,
    yet runs at hashcat's DEFAULT workload (full speed; no ``-w`` throttle). When
    ``False`` (a FOREGROUND/blocking crack: the operator is watching, the REPL is
    blocked, nothing concurrent to protect) the crack runs at FULL speed with none
    of those levers, because faster completion is strictly better with no
    interactivity to starve.
    """
    from adscan_internal.services.hashcat_coordination import (  # noqa: PLC0415
        hashcat_slot,
    )
    from adscan_internal.services.hashcat_service import (  # noqa: PLC0415
        HashcatCrackingService,
    )

    run_command = getattr(shell, "run_command", None)
    if run_command is None:
        return {}

    mode = str(mode or "").strip()
    show_file = f"{hash_file}.show"
    try:
        rules_args = ["-r", rules_path] if rules_path else []
        # --status --status-json --status-timer N: the non-interactive equivalent
        # of the interactive "s" key — hashcat emits a machine-readable JSON
        # status object every N seconds so a running crack's progress + ETA can
        # be parsed (see parse_hashcat_status_json) and surfaced in the harvest
        # row. Harmless to the crack itself; ignored when unparseable.
        status_args = [
            "--status", "--status-json", "--status-timer", _STATUS_TIMER_SECONDS,
        ]
        # Isolation applies ONLY to a BACKGROUND crack (the operator is driving
        # the REPL while this runs on a worker thread). A FOREGROUND/blocking
        # crack (background=False) runs at FULL speed — no launch prefix, no
        # device/core restriction — because there is no concurrent interactivity
        # to protect and faster completion is strictly better. See the module
        # comment block above the constants for why each lever matters. NB: no
        # ``-w`` workload profile is ever forced — the background crack runs at
        # hashcat's DEFAULT workload (full speed); responsiveness comes from the
        # resource isolation below (GPU-free CPU / a reserved-core REPL), not from
        # throttling the crack.
        #
        # Order: taskset (core reservation) → nice (priority) → hashcat, all as
        # command-string prefixes so clean-env / hashcat_slot / streaming
        # (on_line, silence_timeout) / telemetry are untouched.
        if background:
            launch_prefix = [*_cpu_reservation_prefix(), *_nice_prefix()]
            device_args = _gpu_only_device_args()
        else:
            launch_prefix = []
            device_args = []
        crack_argv = [
            *launch_prefix, "hashcat", "-m", mode, "--username",
            *status_args, *device_args, *rules_args,
            hash_file, wordlist,
        ]
        crack_cmd = " ".join(shlex.quote(str(a)) for a in crack_argv)
        # The --show pass is a quick potfile lookup (no kernels), so it only
        # inherits the launch prefix (taskset/nice) — not the device flags — and
        # only when the crack itself was launched with isolation.
        show_argv = [
            *launch_prefix, "hashcat", "-m", mode, "--username",
            "--outfile-format", "2", hash_file, "--show",
        ]
        show_cmd = " ".join(shlex.quote(str(a)) for a in show_argv)
        # STREAM the crack: a per-line handler parses each --status-json tick the
        # moment hashcat emits it (via run_command's on_line streaming mode) and
        # feeds it to the runtime, so the in-progress harvest row shows hashcat's
        # REAL live ETA/progress — not just a value read after the crack exits.
        # on_line is only passed when a status_sink is present, so a shell whose
        # run_command predates the streaming param (or a test double) is
        # unaffected; the completion / clean-env / hashcat_slot / telemetry paths
        # are identical to the blocking run.
        # No overall elapsed cap on the crack (``timeout=None``): a legitimate
        # long crack must run to completion. When streaming (the production path,
        # a status_sink is always supplied) the crack is instead bounded by an
        # output-SILENCE watchdog — killed only if hashcat emits nothing at all
        # for the silence window, which reliably means wedged while a
        # steadily-progressing crack keeps emitting --status-json ticks.
        crack_kwargs: dict[str, Any] = {"timeout": None}
        if status_sink is not None:
            crack_kwargs["on_line"] = _make_status_line_handler(status_sink)
            crack_kwargs["silence_timeout"] = _CRACK_SILENCE_TIMEOUT_SECONDS
        # Serialize the real crack + its --show read against every other
        # hashcat launch (a concurrent crack, or the best-effort benchmark
        # warm-up) via the shared single-instance slot. block=True: a real
        # crack always eventually runs and never collides with hashcat's
        # single-instance lock.
        with hashcat_slot(block=True):
            # We now HOLD the single-instance slot: hashcat is about to run. Mark
            # this runtime as holding it so snapshot() reports "cracking" (not
            # "queued") for the duration, and clear the mark on release. This only
            # OBSERVES the hold — the slot mechanics are untouched.
            if slot_state_sink is not None:
                slot_state_sink(True)
            try:
                crack_result = run_command(crack_cmd, **crack_kwargs)
                show_result = run_command(show_cmd, timeout=_SHOW_PASS_TIMEOUT_SECONDS)
            finally:
                if slot_state_sink is not None:
                    slot_state_sink(False)
        # Backstop: if the shell's run_command did not support streaming, re-parse
        # the accumulated stdout for the last status so the row still updates.
        if status_sink is not None and crack_result is not None:
            _emit_last_status(crack_result, status_sink)
        if show_result is None:
            # crack-show: the --show completion pass returned no result object —
            # a match written to the potfile would then be invisible to the parse.
            print_info_debug(f"crack-show: mode={mode} show_result=None (no matches parsed)")
            return {}
        show_output = getattr(show_result, "stdout", "") or ""
        if not show_output.strip():
            print_info_debug(
                f"crack-show: mode={mode} empty --show output "
                f"(exit={getattr(show_result, 'returncode', '?')}) — no matches parsed"
            )
            return {}

        with open(show_file, "w", encoding="utf-8") as handle:
            handle.write(show_output)

        service = HashcatCrackingService(shell)
        result = service.extract_creds_from_hash(show_file)
        creds = dict(result.credentials or {}) if result is not None else {}
        # crack-show: the pivotal diagnostic for "the crack cracked but nothing was
        # harvested" — how many non-empty --show lines vs how many creds the parser
        # extracted. A non-zero line count with zero creds pinpoints a parse
        # mismatch (the naive user:pass split vs the real --username --show shape).
        nonempty_lines = sum(1 for ln in show_output.splitlines() if ln.strip())
        marked_users = ", ".join(mark_sensitive(u, "user") for u in creds)
        print_info_debug(
            f"crack-show: mode={mode} show_lines={nonempty_lines} "
            f"parsed_creds={len(creds)} users={marked_users}"
        )
        return creds
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return {}
    finally:
        try:
            if os.path.exists(show_file):
                os.remove(show_file)
        except OSError as exc:  # noqa: BLE001 — cleanup is best-effort
            telemetry.capture_exception(exc)


def _normalize_tiers(
    wordlist_tiers: Optional[list[str]], effort_tiers: Optional[list[EffortTier]]
) -> list[tuple[str, Optional[str]]]:
    """Adapt either the legacy flat wordlist-path list or the newer
    rule-aware EffortTier ladder into a single (wordlist, rules_path) tuple
    sequence the crack loop walks. Callers that resolved an effort
    (services/cracking_wordlist_policy.resolve_effort) pass effort_tiers;
    everything else keeps passing wordlist_tiers, so existing callers (and
    their tests) are unaffected — this function is purely additive."""
    if effort_tiers:
        return [(t.base_path, t.rule_path) for t in effort_tiers]
    return [(w, None) for w in (wordlist_tiers or [])]


class CrackingJobRuntime:
    """Live cracking worker; implements the JobRuntime protocol."""

    def __init__(
        self,
        shell: Any,
        *,
        domain: str,
        user: str,
        hash_file: str,
        mode: Optional[str] = None,
        ntlm_version: str = "",
        wordlist_tiers: Optional[list[str]] = None,
        effort_tiers: Optional[list[EffortTier]] = None,
        background: bool = False,
        max_effort: str = "",
        sink: JobResultSink,
        job_id: str,
    ) -> None:
        self.shell = shell
        self.domain = domain
        self.user = user
        # The concrete hashcat mode this job cracks under (any supported mode).
        # ``ntlm_version`` is retained for backward compatibility / labels and
        # is used to derive the mode when ``mode`` is not given explicitly.
        self.ntlm_version = str(ntlm_version or "")
        self.mode = _resolve_runtime_mode(mode, self.ntlm_version)
        self.hash_file = hash_file
        self.tiers: list[tuple[str, Optional[str]]] = _normalize_tiers(
            wordlist_tiers, effort_tiers
        )
        # Per-tier estimated seconds for THIS mode, aligned with self.tiers, so
        # snapshot() can compute a live ETA/progress from wall-clock vs the
        # benchmark estimate. Only the EffortTier ladder carries estimates; the
        # legacy bare-wordlist path has none (ETA then degrades to "cracking …").
        if effort_tiers:
            self._tier_estimates: list[Optional[float]] = [
                t.estimated_seconds_per_mode.get(self.mode) for t in effort_tiers
            ]
        else:
            self._tier_estimates = [None] * len(self.tiers)
        # Live in-flight tier state (method + wall-clock start + estimate) and the
        # last parsed hashcat status, both read by snapshot() for the harvest row.
        self._live_lock = threading.Lock()
        self._live: dict[str, Any] = {}
        self._last_status: dict[str, Any] = {}
        # Whether this crack currently HOLDS the single-instance hashcat slot
        # (hashcat running) vs is alive-but-waiting for it (queued behind another
        # crack). Set True on slot acquire / False on release by _on_slot_state;
        # read by snapshot() to report the crack's phase. Guarded by _live_lock.
        self._holds_slot = False
        # Foreground vs background routing (Phase 2). A BACKGROUND crack (the
        # off-flow job launched via ``enqueue_cracking_job``) must NOT
        # auto-``add_credential`` + chain auth-enum from a worker thread — it
        # hands the recovered secret to the scan-end harvest review, where the
        # operator decides. A FOREGROUND crack (``background=False``, the
        # default — the operator is watching) keeps today's auto-add behaviour.
        self.background = bool(background)
        # Highest effort tier this crack ladder attempts, stamped on the emitted
        # JobResult so the harvest record can gate escalation to strictly higher
        # tiers. Empty for a legacy/basic wordlist pass.
        self.max_effort = str(max_effort or "")
        self.sink = sink
        self.job_id = job_id
        self.cracked = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Guards the worker-thread completion guarantee (see _run_crack_tiers):
        # every exit path emits EXACTLY ONE terminal JobResult. Set the moment a
        # cracked / uncracked result is emitted so the crash failsafe never
        # double-emits after a normal completion.
        self._terminal_emitted = False

    def start(self) -> bool:
        self._thread = threading.Thread(
            target=_run_crack_tiers, args=(self,),
            name=f"job-cracking-{self.user}", daemon=True,
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def snapshot(self) -> dict[str, Any]:
        method, progress_pct, eta_seconds = self._live_progress_eta()
        with self._live_lock:
            holds_slot = self._holds_slot
        # "cracking" = this runtime holds the hashcat slot (hashcat is running).
        # "queued"   = alive but not holding it — waiting behind another crack for
        #              the single-instance slot, or not yet started a tier. The
        #              view renders "queued" so a waiting crack no longer reads as
        #              a false "cracking".
        phase = "cracking" if holds_slot else "queued"
        snap: dict[str, Any] = {"cracked": self.cracked, "user": self.user, "phase": phase}
        if method:
            snap["method"] = method
        if progress_pct is not None:
            snap["progress_pct"] = progress_pct
        if eta_seconds is not None:
            snap["eta_seconds"] = eta_seconds
        return snap

    def is_alive(self) -> bool:
        return bool(self._thread is not None and self._thread.is_alive())

    def _emit_terminal_result(self, result: "JobResult") -> None:
        """Emit the crack's ONE terminal JobResult through the sink.

        Records that a terminal result has been emitted so the worker-thread
        completion guarantee in :func:`_run_crack_tiers` never appends a second
        (failsafe) terminal result after a normal cracked / uncracked emit. The
        result MUST already carry ``terminal=True`` — the sink transitions the
        job out of ``registry.active()`` on it.
        """
        self._terminal_emitted = True
        # crack-complete: greppable, --debug-only. Confirms the runtime DID emit a
        # terminal result, its status, and (background) whether a secret rode along
        # — the first checkpoint when diagnosing a "cracked credential vanished".
        try:
            detail = result.detail if isinstance(result.detail, dict) else {}
            users = detail.get("users") if isinstance(detail.get("users"), list) else []
            print_info_debug(
                "crack-complete: emitting terminal result "
                f"job_id={self.job_id} status={detail.get('status')} "
                f"user={mark_sensitive(str(detail.get('user') or ''), 'user')} "
                f"secret_present={bool(detail.get('secret'))} "
                f"user_count={len(users)}"
            )
        except Exception as exc:  # noqa: BLE001 — a debug log must never break the emit
            telemetry.capture_exception(exc)
        self.sink(result)

    # ── live in-flight tier tracking (for the in-progress harvest row) ────────

    def _begin_tier(self, method: str, estimate: Optional[float]) -> None:
        with self._live_lock:
            self._live = {
                "method": method,
                "started": time.time(),
                "estimate": float(estimate) if estimate else None,
            }
            self._last_status = {}

    def _on_tier_status(self, status: dict) -> None:
        if not isinstance(status, dict):
            return
        with self._live_lock:
            self._last_status = dict(status)

    def _on_slot_state(self, held: bool) -> None:
        """Record whether this crack now HOLDS the single-instance hashcat slot.

        Called by :func:`_run_hashcat_tier` with ``True`` the moment the slot is
        acquired (hashcat is running) and ``False`` on release. Snapshot() reads
        this to report ``"cracking"`` (holds it) vs ``"queued"`` (alive but
        waiting behind another crack). Does NOT touch the slot mechanics — it
        only observes this runtime's own hold. On acquire the benchmark wall-
        clock is (re)started so a long queue wait never inflates the pre-first-
        tick progress estimate. Thread-safe.
        """
        with self._live_lock:
            self._holds_slot = bool(held)
            if held and self._live:
                self._live["started"] = time.time()

    def _end_tier(self) -> None:
        with self._live_lock:
            self._live = {}
            self._last_status = {}

    def _live_progress_eta(
        self,
    ) -> "tuple[str, Optional[float], Optional[int]]":
        """Return ``(method, progress_pct, eta_seconds)`` for the running tier.

        Fallback order (best-effort — any missing input yields ``None`` so the
        row shows a plain ``cracking …``):

        1. **The live hashcat ``--status-json`` tick** (real, benchmark-
           independent) — now streamed in the moment hashcat emits it, so it is
           preferred as soon as the first tick arrives.
        2. **The benchmark wall-clock estimate** (elapsed vs the tier's estimated
           seconds) — the pre-first-tick fallback for the effort-tier ladder.
        3. Neither → ``None`` (plain ``cracking …``).
        """
        with self._live_lock:
            live = dict(self._live)
            last = dict(self._last_status)
        method = str(live.get("method") or "")
        started = live.get("started")
        estimate = live.get("estimate")
        progress_pct: Optional[float] = None
        eta_seconds: Optional[int] = None
        # 1) Live hashcat status first — the ground-truth progress/ETA the KDC-
        #    independent crack itself reports each --status-timer tick.
        if last:
            lp = last.get("progress_pct")
            le = last.get("eta_seconds")
            if isinstance(lp, (int, float)) and lp < 100:
                progress_pct = float(lp)
            if isinstance(le, (int, float)):
                eta_seconds = int(le)
        # 2) Before any tick has arrived, fall back to the benchmark estimate.
        if (
            progress_pct is None
            and eta_seconds is None
            and isinstance(started, (int, float))
            and isinstance(estimate, (int, float))
            and estimate > 0
        ):
            elapsed = max(0.0, time.time() - started)
            progress_pct = max(0.0, min(100.0, 100.0 * elapsed / estimate))
            eta_seconds = max(0, int(estimate - elapsed))
        return method, progress_pct, eta_seconds


def _run_crack_tiers(runtime: "CrackingJobRuntime") -> None:
    """Thread body: walk the tiers, stop on first match, emit a result.

    Wrapped in ``background_console_context`` so the hashcat ``run_command``
    DEBUG chatter emitted on this worker thread never paints the live console
    or collides with an interactive prompt — it is telemetered + deferred for
    the foreground to flush.

    Completion guarantee: the ladder normally emits EXACTLY ONE terminal
    JobResult (cracked or uncracked) via ``_emit_terminal_result``. If any
    unhandled exception escapes the ladder before that emit, this wrapper emits
    a terminal ``failed`` result instead — so the job ALWAYS leaves
    ``registry.active()`` (never wedged "running" forever) and the failure
    surfaces on the foreground drain instead of vanishing silently. This is the
    structural backstop for the "crack finished but the job hung + the
    credential disappeared" class of bug: a worker thread that dies without
    emitting used to leave the job stuck running with nothing persisted.
    """
    from adscan_core.rich_output import background_console_context  # noqa: PLC0415

    with background_console_context(f"cracking-{runtime.user}"):
        try:
            _run_crack_tiers_impl(runtime)
        except Exception as exc:  # noqa: BLE001 — never let a worker thread die silently
            telemetry.capture_exception(exc)
            if not runtime._terminal_emitted:
                # crack-complete: the ladder crashed before emitting its terminal
                # result — emit a terminal ``failed`` so the job leaves active()
                # and the operator sees the crack did not complete cleanly.
                try:
                    print_info_debug(
                        "crack-complete: ladder raised before terminal emit "
                        f"job_id={runtime.job_id} user={runtime.user} error={exc}"
                    )
                except Exception as log_exc:  # noqa: BLE001
                    telemetry.capture_exception(log_exc)
                runtime._end_tier()
                runtime._emit_terminal_result(
                    JobResult(
                        job_id=runtime.job_id, kind="cracking", scope=runtime.user,
                        summary=(
                            f"{_mode_label(runtime.mode)} for "
                            f"{mark_sensitive(runtime.user, 'user')} did not complete"
                        ),
                        detail={
                            "status": "failed", "user": runtime.user,
                            "mode": runtime.mode, "version": runtime.ntlm_version,
                            "max_effort": runtime.max_effort,
                            "hash_file": runtime.hash_file,
                        },
                        terminal=True,
                    )
                )


def _persist_matches(runtime: "CrackingJobRuntime", matches: dict) -> list[str]:
    """Route every cracked principal, foreground vs background; return the users.

    A roast hashfile can carry MANY principals in ONE hashcat pass, so this
    credits every match rather than just the job's primary user (the old
    NetNTLM single-user assumption).

    Routing (Phase 2):

    * ``runtime.background`` is ``False`` (a FOREGROUND crack — the operator is
      watching): keep today's behaviour — ``add_credential`` for every match,
      ``ui_silent`` + no follow-up prompts, still persisted + verified.
    * ``runtime.background`` is ``True`` (a BACKGROUND job on a worker thread):
      do NOT ``add_credential`` and do NOT chain auth-enum. The recovered
      secrets ride the emitted JobResult to the foreground, which persists a
      harvest record and lets the OPERATOR activate them from the scan-end
      review. This is the hard invariant — a background thread never
      auto-owns a credential nor prints/prompts.
    """
    cracked_users: list[str] = []
    for user, password in matches.items():
        if not password:
            continue
        if not runtime.background:
            try:
                runtime.shell.add_credential(
                    runtime.domain,
                    user,
                    password,
                    ui_silent=True,
                    prompt_for_user_privs_after=False,
                    skip_user_privs_enumeration=True,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        cracked_users.append(user)
    return cracked_users


def _run_crack_tiers_impl(runtime: "CrackingJobRuntime") -> None:
    label = _mode_label(runtime.mode)
    last_method = ""
    for idx, (wordlist, rules_path) in enumerate(runtime.tiers):
        if runtime._stop.is_set():
            break
        if not os.path.exists(wordlist):
            continue
        last_method = _method_label(wordlist, rules_path)
        estimate = (
            runtime._tier_estimates[idx]
            if idx < len(runtime._tier_estimates)
            else None
        )
        runtime._begin_tier(last_method, estimate)
        try:
            matches = _run_hashcat_tier(
                runtime.shell, runtime.hash_file, wordlist, runtime.mode,
                rules_path=rules_path, status_sink=runtime._on_tier_status,
                slot_state_sink=runtime._on_slot_state,
                background=runtime.background,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            matches = {}
        cracked_users = _persist_matches(runtime, matches) if matches else []
        if cracked_users:
            runtime.cracked = len(cracked_users)
            primary = runtime.user if runtime.user in cracked_users else cracked_users[0]
            extra = len(cracked_users) - 1
            summary = f"Cracked {label} for {mark_sensitive(primary, 'user')}"
            if extra > 0:
                summary += f" (+{extra} more)"
            # A BACKGROUND crack did NOT add_credential — carry the recovered
            # secret(s) to the foreground so the harvest record (and the
            # operator's scan-end activation) can use them. Cleartext at rest
            # in the workspace registry, exactly like domains_data; never
            # printed (the cracking notification line omits it).
            detail = {
                "status": "cracked", "user": primary,
                "users": cracked_users,
                "domain": runtime.domain, "wordlist": os.path.basename(wordlist),
                "method": last_method,
                "mode": runtime.mode, "version": runtime.ntlm_version,
                "max_effort": runtime.max_effort, "hash_file": runtime.hash_file,
            }
            if runtime.background:
                detail["secret"] = str(matches.get(primary) or "")
                detail["secrets"] = {u: str(matches.get(u) or "") for u in cracked_users}
            runtime._end_tier()
            # Terminal emit: the crack ladder produced a match and stops here.
            # ``terminal=True`` transitions the job to a terminal registry state at
            # the sink, so a finished crack LEAVES ``registry.active()`` instead of
            # lingering as "running" forever (until session finalize).
            runtime._emit_terminal_result(
                JobResult(
                    job_id=runtime.job_id, kind="cracking", scope=runtime.user,
                    summary=summary,
                    detail=detail,
                    terminal=True,
                )
            )
            return
    runtime._end_tier()
    # Terminal emit: every tier is exhausted with no match — the ladder is done.
    # ``terminal=True`` marks the job terminal at the sink (same rationale as the
    # cracked emit above), so an uncracked crack does not linger in active().
    runtime._emit_terminal_result(
        JobResult(
            job_id=runtime.job_id, kind="cracking", scope=runtime.user,
            summary=(
                f"{label} for {mark_sensitive(runtime.user, 'user')} not cracked"
            ),
            detail={
                "status": "uncracked", "user": runtime.user,
                "method": last_method,
                "mode": runtime.mode, "version": runtime.ntlm_version,
                "max_effort": runtime.max_effort, "hash_file": runtime.hash_file,
            },
            terminal=True,
        )
    )
