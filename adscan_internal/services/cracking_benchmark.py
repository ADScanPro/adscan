"""Hardware benchmark SSOT for the cracking-effort engine.

Runs `hashcat -b` once per (mode, device-class) and caches the measured H/s
at ~/.adscan/benchmark.json, keyed by a hardware fingerprint with a 30-day
TTL. `cracking_wordlist_policy.resolve_effort()` reads this cache to pick the
largest (wordlist x rules) keyspace that fits each effort tier's time budget
on the ACTUAL hardware running the scan -- see
docs/superpowers/specs/2026-07-07-cracking-effort-engine-design.md.

Only OBSERVED numbers are ever persisted. A run that fails outright falls
back to the prior (possibly stale) cache's rates when one exists; with no
cache at all it returns None, and every caller treats None as "force the
fast tier" -- never guess a keyspace that could hang for hours.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core import telemetry

# The four hashcat modes ADscan cracks: NetNTLMv2, NetNTLMv1, Kerberoast
# (TGS-REP, RC4), AS-REP Roasting (RC4). Etype-derived AES modes
# (19600/19700/19800/19900) are NOT separately benchmarked -- they route
# through the same base rates via the mode-aware rule cap in
# cracking_wordlist_policy (AES is 20-40x slower than RC4, already handled by
# the existing _AES_ROAST_HASHCAT_MODES policy in cli/cracking.py).
BENCHMARK_MODES: tuple[str, ...] = ("5600", "5500", "13100", "18200")

# v2 adds the ``complete`` flag: a record is only a full-hardware-hit when every
# (mode, device) pair was attempted in one uninterrupted pass. A ``block=True``
# crack now yields the slot promptly (services/hashcat_coordination), so a
# warm-up sweep is routinely PAUSED mid-way — its measured pairs are persisted
# as ``complete=False`` and the next scan RESUMES the remaining pairs instead of
# re-sweeping from scratch. Bumping to 2 busts any v1 cache (re-measured once).
_BENCHMARK_SCHEMA_VERSION = 2
_BENCHMARK_TTL_SECONDS = 30 * 86400
_DEVICE_FLAGS: dict[str, str] = {"gpu": "2", "cpu": "1"}
_DEVICE_NAME_LINE_RE = re.compile(r"Name\s*\.+?:\s*(.+)")
# ``hashcat -I`` prints a ``Type...........: GPU`` line per backend device
# (1=CPU / 2=GPU in hashcat's ``-D`` numbering). Parsing it lets a background
# crack pin itself GPU-only (``-D 2``) so the CPU cores stay free for the REPL.
_DEVICE_TYPE_LINE_RE = re.compile(r"Type\s*\.+?:\s*(\w+)")


@dataclass(frozen=True)
class BenchmarkRecord:
    """A single persisted `hashcat -b` measurement for this machine.

    ``complete`` is ``True`` only when every (mode, device) pair was attempted
    in one uninterrupted sweep. An interrupted warm-up (a real crack took the
    GPU) persists its measured pairs with ``complete=False`` so a later scan
    resumes the remaining pairs rather than re-sweeping from scratch.
    """

    schema_version: int
    fingerprint: str
    device_names: tuple[str, ...]
    measured_at: str
    rates: dict[str, dict[str, float]] = field(default_factory=dict)
    complete: bool = False
    # Whether ``hashcat -I`` reported at least one GPU-type backend device on
    # this machine, captured during the benchmark probe. ``None`` on legacy
    # records written before this field existed — the GPU-detection SSOT
    # (:func:`detect_gpu_present`) then falls back to the measured GPU rates, so
    # no schema bump / forced re-sweep is needed.
    has_gpu: bool | None = None


# --- fingerprint ---------------------------------------------------------


def extract_device_names(probe_text: str) -> tuple[str, ...]:
    """Extract every 'Name...........: <device>' line from `hashcat -I` output."""
    if not probe_text:
        return ()
    names: list[str] = []
    for line in probe_text.splitlines():
        match = _DEVICE_NAME_LINE_RE.search(line)
        if match:
            name = match.group(1).strip()
            if name:
                names.append(name)
    return tuple(sorted(set(names)))


def probe_reports_gpu(probe_text: str) -> bool:
    """True when ``hashcat -I`` reports at least one GPU-type backend device.

    Parses the ``Type...........: GPU`` lines of the device enumeration. Used by
    :func:`detect_gpu_present` so a background crack can be pinned GPU-only
    (``-D 2``) — keeping the CPU cores free for the interactive REPL — only when a
    GPU is actually present.
    """
    if not probe_text:
        return False
    for line in probe_text.splitlines():
        match = _DEVICE_TYPE_LINE_RE.search(line)
        if match and match.group(1).strip().lower() == "gpu":
            return True
    return False


def compute_fingerprint(probe_text: str) -> str:
    """A stable, order-independent fingerprint of the detected compute devices.

    Changes whenever the GPU/CPU set changes (moved to different hardware, an
    appliance was cloned onto new hardware) -- the freshness check in
    is_fresh() forces a re-probe on mismatch.
    """
    names = extract_device_names(probe_text)
    digest_input = "|".join(sorted(names)).encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()[:16]


# --- cache IO --------------------------------------------------------------


def _benchmark_cache_path() -> Path:
    from adscan_core.paths import get_adscan_home  # noqa: PLC0415

    # Persist under ``state/`` -- NOT the ``/opt/adscan`` root. The launcher
    # bind-mounts only SPECIFIC subdirs of ``/opt/adscan`` to the host
    # (``state/``, ``logs/``, ``workspaces/``, ``tools/``, ``wordlists/``, ...);
    # the ``/opt/adscan`` ROOT itself is the container's EPHEMERAL writable
    # layer, wiped on every ``docker run --rm``. A cache written to the root
    # (the previous behaviour) was written correctly inside the container but
    # vanished when the container exited -- so every scan re-ran the full
    # ``hashcat -b`` sweep. ``state/`` maps to ``~/.adscan/state`` on the host
    # (see adscan_launcher/docker_runtime.py ``state_host_dir``) and is the
    # natural home for machine-level persisted state, so the record now survives
    # across containers and the warm-cache fast path actually hits.
    return get_adscan_home() / "state" / "benchmark.json"


def _load_cache() -> BenchmarkRecord | None:
    path = _benchmark_cache_path()
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return BenchmarkRecord(
            schema_version=int(data.get("schema_version", 0)),
            fingerprint=str(data.get("fingerprint", "")),
            device_names=tuple(data.get("device_names") or ()),
            measured_at=str(data.get("measured_at", "")),
            rates={
                str(mode): {str(k): float(v) for k, v in (rates or {}).items()}
                for mode, rates in (data.get("rates") or {}).items()
            },
            # Default False: an unknown/legacy completeness triggers a resume
            # rather than trusting a possibly-partial record as a full hit.
            complete=bool(data.get("complete", False)),
            # None (missing) on legacy records → detect_gpu_present falls back to
            # the measured GPU rates.
            has_gpu=(
                None if data.get("has_gpu") is None else bool(data.get("has_gpu"))
            ),
        )
    except Exception as exc:  # noqa: BLE001 -- a corrupt cache is cold, never crashes
        telemetry.capture_exception(exc)
        return None


def _save_cache(record: BenchmarkRecord) -> None:
    from rich.markup import escape  # noqa: PLC0415

    from adscan_core.rich_output import print_info_debug, print_warning  # noqa: PLC0415

    path = _benchmark_cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": record.schema_version,
            "fingerprint": record.fingerprint,
            "device_names": list(record.device_names),
            "measured_at": record.measured_at,
            "rates": record.rates,
            "complete": record.complete,
            "has_gpu": record.has_gpu,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        # Visible under --debug with the RESOLVED absolute path so a future
        # "cache never persists" investigation reads the truth immediately.
        print_info_debug(
            f"benchmark-cache: saved complete={record.complete} "
            f"modes={len(record.rates)} to {escape(str(path))}"
        )
    except Exception as exc:  # noqa: BLE001 -- persistence is best-effort
        telemetry.capture_exception(exc)
        # Surface the failure LOUDLY, not just via telemetry: a benchmark cache
        # that never lands means ``hashcat -b`` re-sweeps every scan, and a
        # silent write error (perms / wrong path / serialisation) is otherwise
        # invisible to the operator.
        print_warning(
            f"benchmark-cache: FAILED to persist to {escape(str(path))}: "
            f"{escape(str(exc))}"
        )


def _utcnow_iso() -> str:
    return _iso_from_epoch(time.time())


def _iso_from_epoch(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _parse_iso(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, TypeError):
        return None


# --- freshness ---------------------------------------------------------


def is_fresh(
    record: BenchmarkRecord | None,
    *,
    current_fingerprint: str | None,
    now: float | None = None,
) -> bool:
    """True when `record` is usable as-is: same schema, same hardware, within TTL.

    A `current_fingerprint` of None means fingerprint DETECTION failed (not
    "no devices") -- per the design spec's error-handling section this is
    treated as a mismatch, forcing a fresh probe rather than trusting a stale
    record against unknown hardware.
    """
    if record is None:
        return False
    if record.schema_version != _BENCHMARK_SCHEMA_VERSION:
        return False
    if current_fingerprint is None or record.fingerprint != current_fingerprint:
        return False
    measured_at = _parse_iso(record.measured_at)
    if measured_at is None:
        return False
    current = now if now is not None else time.time()
    return (current - measured_at) < _BENCHMARK_TTL_SECONDS


# --- hashcat -b runner -------------------------------------------------


_SPEED_UNIT_MULTIPLIERS: dict[str, float] = {
    "H/s": 1.0,
    "kH/s": 1e3,
    "MH/s": 1e6,
    "GH/s": 1e9,
    "TH/s": 1e12,
}


def _parse_machine_readable_speed(output: str, mode: str) -> float | None:
    """Parse `hashcat -b --machine-readable` lines: <dev>:<mode>:...:<speed>."""
    total = 0.0
    found = False
    for line in (output or "").splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 2 and parts[1] == str(mode):
            try:
                total += float(parts[-1])
                found = True
            except ValueError:
                continue
    return total if found and total > 0 else None


def _parse_human_readable_speed(output: str) -> float | None:
    total = 0.0
    found = False
    for line in (output or "").splitlines():
        if "Speed.#" not in line or "/s" not in line:
            continue
        for unit, multiplier in _SPEED_UNIT_MULTIPLIERS.items():
            if unit in line:
                try:
                    number = float(line.split(unit)[0].split()[-1])
                except (ValueError, IndexError):
                    continue
                total += number * multiplier
                found = True
                break
    return total if found else None


def _parse_benchmark_speed(output: str, mode: str) -> float | None:
    return _parse_machine_readable_speed(output, mode) or _parse_human_readable_speed(
        output
    )


def _run_single_benchmark(shell: Any, mode: str, device_flag: str) -> float | None:
    from adscan_internal.cli.tools_env import (  # noqa: PLC0415
        maybe_wrap_hashcat_for_container,
    )
    from adscan_internal.services.background_jobs.cracking_job import (  # noqa: PLC0415
        _cpu_reservation_prefix,
        _nice_prefix,
    )

    # Run the warm-up benchmark with the SAME resource isolation as a real
    # background crack, for two reasons:
    #   * it pegs the CPU/GPU exactly like a real crack, so at normal OS priority
    #     it would lag the interactive REPL during the warm-up sweep;
    #   * it must measure at the SAME workload the crack runs at so the derived
    #     ETA/effort estimate matches the real crack speed. Neither the benchmark
    #     nor the crack forces a ``-w`` profile anymore — both run at hashcat's
    #     DEFAULT workload — so the same-workload invariant holds (both default)
    #     without the old ``-w 1`` throttle that cost ~15% crack speed.
    # The prefixes reuse the crack's SSOT levers (services/background_jobs/
    # cracking_job): ``nice`` for priority + a ``taskset`` core reservation on a
    # GPU-less host, mirroring the crack's REPL-responsiveness isolation. All
    # degrade gracefully to no-ops when nice / taskset are unavailable; the
    # ``-D <device_flag>`` device probe is left exactly as-is.
    argv = [
        *_cpu_reservation_prefix(),
        *_nice_prefix(),
        "hashcat",
        "-b",
        "-m",
        mode,
        "-D",
        device_flag,
        "--machine-readable",
        "--quiet",
    ]
    cmd = " ".join(shlex.quote(a) for a in argv)
    try:
        wrapped = maybe_wrap_hashcat_for_container(cmd)
        result = shell.run_command(wrapped, timeout=120)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None
    if result is None:
        return None
    combined = (
        f"{getattr(result, 'stdout', '') or ''}\n{getattr(result, 'stderr', '') or ''}"
    )
    return _parse_benchmark_speed(combined, mode)


def _probe_devices(shell: Any) -> str | None:
    from adscan_internal.cli.tools_env import (  # noqa: PLC0415
        maybe_wrap_hashcat_for_container,
    )

    try:
        wrapped = maybe_wrap_hashcat_for_container("hashcat -I")
        result = shell.run_command(wrapped, timeout=30)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None
    if result is None:
        return None
    return (
        f"{getattr(result, 'stdout', '') or ''}\n{getattr(result, 'stderr', '') or ''}"
    )


def get_or_run_benchmark(
    shell: Any, *, force: bool = False
) -> dict[str, dict[str, float]] | None:
    """Return {mode: {"gpu": h_per_s, "cpu": h_per_s}} for every BENCHMARK_MODES
    entry, running a `hashcat -b` sweep only when the cache is missing, stale
    (TTL/fingerprint/schema), incomplete, or ``force`` is set.

    Best-effort, never raises. On total failure: returns the prior cache's
    rates when one exists (better than nothing), else None (callers treat
    None as "force the fast tier" -- see cracking_wordlist_policy.resolve_effort).

    Two invariants make this cheap and starvation-free:

    * **Warm cache => NO sweep.** A complete, fingerprint-fresh record short-
      circuits before any ``hashcat -b`` runs, so a machine benchmarked once
      never re-sweeps for the TTL (30 days). This is the biggest win — with a
      warm cache there is no GPU contention with a running crack at all.
    * **Cold/partial cache => the sweep YIELDS to any real crack and RESUMES.**
      The best-effort warm-up takes the slot non-blocking, checks
      ``real_crack_pending()`` between pairs, and PAUSES the moment a real crack
      wants the GPU (so the crack runs within one in-flight mode). Whatever it
      measured is PERSISTED (``complete=False``); the next scan resumes the
      remaining pairs instead of re-sweeping. Without this, a scan where a crack
      always contends would discard its work every time and re-sweep forever.
    """
    # Every hashcat launch (probe `-I`, benchmark `-b`) is serialized against
    # real cracks via the shared single-instance slot. (See
    # services/hashcat_coordination.)
    from adscan_internal.services.hashcat_coordination import (  # noqa: PLC0415
        hashcat_slot,
        real_crack_pending,
    )
    from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

    cached = _load_cache()
    print_info_debug(
        f"benchmark-cache: enter force={force} cache_hit={cached is not None} "
        f"cached_complete={cached.complete if cached is not None else None}"
    )

    # Fingerprint the hardware via `hashcat -I`. It needs the single-instance
    # slot; a real crack holding it means we must NOT sweep now anyway, so bail
    # to the cached rates and let a later warm-up retry.
    with hashcat_slot(block=False) as slot:
        probe_text = _probe_devices(shell) if slot else None
    fingerprint = compute_fingerprint(probe_text) if probe_text else None
    if fingerprint is None:
        return cached.rates if cached is not None else None

    fingerprint_matches = cached is not None and cached.fingerprint == fingerprint

    # Warm-cache fast path: a COMPLETE, fingerprint-fresh, within-TTL record —
    # no sweep at all.
    if (
        not force
        and fingerprint_matches
        and cached.complete
        and is_fresh(cached, current_fingerprint=fingerprint)
    ):
        print_info_debug(
            "benchmark-cache: warm-cache HIT (complete + fresh + fingerprint "
            "match) -- no hashcat -b sweep this scan"
        )
        return cached.rates

    # Resume from prior measurements on the SAME hardware (never re-run an
    # already-measured pair — GPU passes are the expensive ones); ``force``
    # re-measures everything from empty.
    resume = fingerprint_matches and not force
    rates: dict[str, dict[str, float]] = (
        {mode: dict(vals) for mode, vals in cached.rates.items()} if resume else {}
    )

    try:
        interrupted = False
        newly_measured = 0
        for mode in BENCHMARK_MODES:
            rates.setdefault(mode, {})
            for device_class, flag in _DEVICE_FLAGS.items():
                if device_class in rates[mode]:
                    continue  # already measured on this hardware — skip (resume)
                # Yield PROMPTLY to any real crack: a block=True crack waiting or
                # holding the slot must get the GPU within one in-flight mode.
                # Checking demand BEFORE re-acquiring also breaks the unfair-RLock
                # tight-loop that would otherwise let the warm-up keep winning.
                if real_crack_pending():
                    interrupted = True
                    break
                with hashcat_slot(block=False) as slot:
                    if not slot:
                        interrupted = True
                        break
                    speed = _run_single_benchmark(shell, mode, flag)
                if speed:
                    rates[mode][device_class] = speed
                    newly_measured += 1
            if interrupted:
                break

        completed_full_pass = not interrupted
        measured_any = any(rates.get(m) for m in BENCHMARK_MODES)
        print_info_debug(
            f"benchmark-cache: sweep done interrupted={interrupted} "
            f"newly_measured={newly_measured} "
            f"completed_full_pass={completed_full_pass} measured_any={measured_any}"
        )

        if not measured_any:
            if completed_full_pass:
                # A full, uninterrupted pass that measured nothing = no usable
                # device / total failure.
                raise RuntimeError("hashcat -b produced no usable rate for any mode")
            return cached.rates if cached is not None else None

        # Persist progress when we measured something new, or when a full pass
        # just flipped an incomplete cache to complete. A pass that only yielded
        # (nothing new, still incomplete) keeps the prior cache untouched.
        if newly_measured > 0 or (
            completed_full_pass and not (cached is not None and cached.complete)
        ):
            record = BenchmarkRecord(
                schema_version=_BENCHMARK_SCHEMA_VERSION,
                fingerprint=fingerprint,
                device_names=extract_device_names(probe_text or ""),
                measured_at=_utcnow_iso(),
                rates=rates,
                complete=completed_full_pass,
                has_gpu=probe_reports_gpu(probe_text or ""),
            )
            _save_cache(record)
            return record.rates
        print_info_debug(
            "benchmark-cache: persist SKIPPED (nothing new measured, still "
            "incomplete) -- prior cache kept as-is"
        )
        return rates
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return cached.rates if cached is not None else None


# --- estimates artifact + non-blocking warm-up ----------------------------
#
# The interactive effort selector and the web effort cards both want INSTANT
# real time-estimates. Two pieces make that possible:
#
#   1. warm_benchmark_async(shell) -- kicked off ONCE at scan start on a daemon
#      thread so the hardware benchmark (30s-2min the first time, a no-op when
#      cached-fresh) never blocks the scan and is warm by the time the operator
#      reaches the crack step. NOT a background-JOB (no per-scan lifecycle) --
#      a hardware warm-up is a plain guarded daemon thread, deliberately NOT
#      routed through BackgroundJobRegistry.
#   2. cracking_benchmark_estimates.json -- a small per-workspace artifact
#      (per hash-mode x per effort tier) written best-effort once the benchmark
#      resolves. The WEB consumes this to render the same effort cards; the
#      shape SSOT is cracking_wordlist_policy.build_estimates_payload.

_ESTIMATES_ARTIFACT_NAME = "cracking_benchmark_estimates.json"


def load_cached_benchmark() -> dict[str, dict[str, float]] | None:
    """Return the persisted benchmark rates WITHOUT running hashcat.

    The instant, best-effort read the interactive effort selector uses so it can
    show real estimates the moment the cache is warm (freshness/TTL is not
    re-checked here -- a slightly stale rate on the same hardware is a fine
    ballpark, and a hardware change is caught by ``get_or_run_benchmark`` on the
    next real resolve). ``None`` when no cache exists yet.
    """
    record = _load_cache()
    if record is None or not record.rates:
        return None
    return record.rates


def detect_gpu_present() -> bool | None:
    """Whether a usable GPU is present, from the benchmark's cached device info.

    Runs NO new hashcat probe — it reads the persisted benchmark record only, so
    a background crack can pin itself GPU-only (``-D 2``) without contending for
    the single-instance hashcat slot.

    Returns:
        ``True``  — a usable GPU is known present.
        ``False`` — the host is known CPU-only.
        ``None``  — unknown (no benchmark yet / inconclusive); the caller treats
        this as "omit ``-D``" so hashcat still runs on whatever devices exist.

    Signal order:

    1. The persisted ``has_gpu`` flag parsed from this machine's ``hashcat -I``
       enumeration during the benchmark warm-up (the direct device signal).
    2. Legacy records (written before ``has_gpu`` existed): infer from the
       measured GPU rates — a positive ``-D 2`` H/s for ANY mode proves a usable
       GPU (the sweep literally ran on it); a COMPLETE sweep with no GPU rate
       anywhere means GPU-absent; an incomplete legacy record is inconclusive.
    """
    record = _load_cache()
    if record is None:
        return None
    if record.has_gpu is not None:
        return bool(record.has_gpu)
    if not record.rates:
        return None
    if any(
        float((vals or {}).get("gpu", 0) or 0) > 0 for vals in record.rates.values()
    ):
        return True
    return False if record.complete else None


def write_benchmark_estimates(
    shell: Any, benchmark: dict[str, dict[str, float]] | None
) -> None:
    """Persist ``cracking_benchmark_estimates.json`` into the workspace.

    Best-effort: a missing workspace dir or any write/serialisation error is
    swallowed + telemetered, never raised. ``benchmark`` is the measured rates
    map (``None`` still writes a provisional artifact from calibration).
    """
    try:
        from adscan_core.paths import get_adscan_home  # noqa: PLC0415
        from adscan_internal.services.cracking_wordlist_policy import (  # noqa: PLC0415
            build_estimates_payload,
        )

        ws_dir = getattr(shell, "current_workspace_dir", None)
        if not ws_dir:
            return

        record = _load_cache()
        hardware_label = (
            ", ".join(record.device_names)
            if record is not None and record.device_names
            else "unknown"
        )
        wordlists_dir = str(get_adscan_home() / "wordlists")
        payload = build_estimates_payload(
            benchmark, wordlists_dir=wordlists_dir, hardware_label=hardware_label
        )
        payload["generated_at"] = _utcnow_iso()

        out_path = Path(ws_dir) / _ESTIMATES_ARTIFACT_NAME
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 -- artifact write is best-effort
        telemetry.capture_exception(exc)


def _warm_benchmark_worker(shell: Any) -> None:
    """Daemon-thread body: resolve the benchmark (no-op when fresh) and write the
    estimates artifact. NEVER prints/prompts; best-effort throughout.

    The whole body runs inside ``background_console_context`` so the ``hashcat
    -b`` / ``hashcat -I`` subprocess chatter (``run_command`` DEBUG lines) can
    never paint the live console mid-scan or collide with an interactive prompt
    -- it is telemetered + deferred for the foreground to flush instead.
    """
    from adscan_core.rich_output import background_console_context  # noqa: PLC0415

    try:
        with background_console_context("benchmark-warmup"):
            rates = get_or_run_benchmark(shell)
            write_benchmark_estimates(shell, rates)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def warm_benchmark_async(shell: Any) -> None:
    """Kick off the hardware benchmark warm-up on a daemon thread, once.

    Idempotent + safe to call from multiple scan-entry points: a per-shell guard
    (``_benchmark_warmup_started``) makes every call after the first a no-op.
    Never blocks the scan, never prints/prompts from the thread, and swallows
    every error (a warm-up failure must never break a scan). The thread itself
    no-ops fast when the cache is already fresh (``get_or_run_benchmark`` returns
    the cached rates without running ``hashcat -b``).
    """
    try:
        if getattr(shell, "_benchmark_warmup_started", False):
            return
        setattr(shell, "_benchmark_warmup_started", True)
        thread = threading.Thread(
            target=_warm_benchmark_worker,
            args=(shell,),
            name="benchmark-warmup",
            daemon=True,
        )
        thread.start()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


__all__ = [
    "BENCHMARK_MODES",
    "BenchmarkRecord",
    "extract_device_names",
    "probe_reports_gpu",
    "compute_fingerprint",
    "detect_gpu_present",
    "is_fresh",
    "get_or_run_benchmark",
    "load_cached_benchmark",
    "write_benchmark_estimates",
    "warm_benchmark_async",
]
