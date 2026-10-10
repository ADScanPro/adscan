"""Measure the rate a real crack ACHIEVES, per (hash mode x rule rung).

The effort engine used to plan against ``hashcat -b``, and that number is not
the rate a crack runs at. Three measured reasons, on the calibration host:

1. ``hashcat -b`` benchmarks the hand-OPTIMIZED kernels (it says so in its own
   banner) and production does not use them. Mode 1000 with the 10k rule file
   measured 2.08 GH/s plain against 7.00 GH/s with ``-O``, about 3.4x.
2. The rest of the gap is the real workload: feeding 94M dictionary words and
   applying rules, against a synthetic kernel loop over a generated mask.
3. The achieved rate depends enormously on how much work each dictionary WORD
   buys, because the GPU amortizes the host's word-feed cost over the
   candidates it derives from that word. Mode 1000 measured 0.017 GH/s
   ruleless, 0.52 GH/s with best64 (77 rules) and 2.12 GH/s with the 10k rule
   file: a 125x spread on one mode and one piece of hardware. The SALT COUNT
   multiplies the same way, because a salted mode tries each candidate against
   every distinct hash: mode 13100 at 77 rules measured 54 MH/s against one
   salt and 143 MH/s against twenty-five, with the keyspace exactly 25x larger.

Point 3 is why an achieved rate is a property of the WORKLOAD (base wordlist x
rule file x number of distinct hashes) and never of the mode alone, so this
module measures and keys on the workload.

The probe runs a short REAL attack with the production argv shape against the
ACTUAL base wordlist, the ACTUAL rule file and, when the caller has it, the
ACTUAL hash file the crack will run. It deliberately does NOT pass ``-O``,
because production does not: the optimized kernels cap the candidate password
length and silently skip longer candidates, so buying that 3.4x would buy it by
dropping coverage without telling anyone, which the Exposure-Validation
doctrine forbids for a lane whose results reach a client deliverable. Do not
add ``-O`` here, and do not add it to the crack to make the two agree.

Two hash-file cases, and they differ in one flag:

* The caller supplies the REAL hash file (every execution lane does). The probe
  runs it as it is, so the salt count is the one the crack will have, and the
  potfile is left ENABLED: if those twelve seconds happen to recover a
  password, the crack that follows reads it out of the potfile. The probe is
  then a head start rather than discarded work.
* No hash file (the estimates artifact). The probe synthesizes a single
  SYNTHETIC target from hashcat's own example hash for the mode, with the
  potfile disabled. The example hash is mutated in its digest field first,
  which keeps the per-mode format valid (only hex characters change, in place)
  while making a match impossible: hashcat's example password is ``hashcat``,
  which the shipped base wordlist contains, so an unmutated example hash
  cracked in 3 seconds and measured nothing.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from typing import Any, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug, print_warning_debug

#: The probe's own wall-clock budget, handed to hashcat as ``--runtime`` so it
#: stops and flushes of its own accord.
#:
#: Twenty seconds, and the reason is a measured ramp. A GPU coming off idle
#: starts at its boost clock and settles to a sustained one: on the calibration
#: host, mode 5600 at 77 rules read 332 MH/s in its first two seconds, held
#: around 322 for twelve, and then fell to 259 by thirty, a 22% decline. A
#: twelve-second window therefore cannot see the settle at all and reads the
#: boost rate as though it were sustained, which is the direction that promises
#: speed the crack will not deliver. Twenty seconds reaches far enough into the
#: decline that the conservative estimator below lands within about 9% of the
#: sustained rate on that worst mode, and within 3% on the rest.
#:
#: Including hashcat's startup (dictionary cache + autotune) one probe costs
#: about 26 seconds of wall clock, paid ONCE per workload and then cached. The
#: alternative to paying it is the estimate the probe replaced, which was wrong
#: by between 1.7 and 15.5 times.
PROBE_RUNTIME_SECONDS = 20

#: ``--status-timer`` for the probe. Four seconds against the twenty-second
#: budget gives about five ticks, which is enough to see the within-run trend
#: rather than one sample of it.
PROBE_STATUS_TIMER_SECONDS = 4

#: hashcat's ``status`` code for a running session, the only ticks that measure
#: the steady state. A ``5`` (exhausted) tick's speed covers a partial final
#: batch and reads low, so it is used only when nothing else is available.
_STATUS_RUNNING = 3

# Modes ADscan cracks, and whether hashcat treats them as SALTED. Read off
# ``hashcat -m <mode> --example-hashes --machine-readable``'s own ``is_salted``
# field on hashcat 7.1.2 and declared here as a constant rather than queried at
# runtime, because the estimate is wanted in the interactive selector on a cold
# box where a subprocess per mode would be paid for a number that does not
# change. The drift that a constant invites is closed by a test that re-reads
# hashcat's own answer whenever hashcat is present on the machine running the
# suite, so a mode whose salting we got wrong fails CI rather than quietly
# misquoting a client's Kerberoast.
#
# An unlisted mode is treated as SALTED, which is the safe direction: a salted
# keyspace is the larger one, so an unknown mode is over-quoted rather than
# under-quoted. Such an estimate is also flagged provisional by the policy.
_MODE_IS_SALTED: dict[str, bool] = {
    "1000": False,  # NTLM
    "3000": False,  # LM
    "5500": True,  # NetNTLMv1
    "5600": True,  # NetNTLMv2
    "13100": True,  # Kerberoast TGS-REP, etype 23
    "18200": True,  # AS-REP, etype 23
    "19600": True,  # Kerberoast TGS-REP, etype 17
    "19700": True,  # Kerberoast TGS-REP, etype 18
    "19800": True,  # AS-REP, etype 17
    "19900": True,  # AS-REP, etype 18
    "31300": True,  # timeroast
}

_HEX_RUN_RE = re.compile(r"[0-9a-fA-F]{16,}")


def achieved_rate_key(
    wordlist: Optional[str],
    rule_path: Optional[str],
    hash_count: Optional[int] = None,
) -> str:
    """The cache key identifying one measured workload, e.g.
    ``"combined_audit_base.txt+OneRuleToRuleThemStill-10k.rule+h12"``.

    Keyed on the two FILES rather than on the effort engine's rule-ladder INDEX,
    for two reasons. The index is a position in a ladder that can be reordered
    or extended, and an entry keyed on it would then describe a workload it was
    never measured against; and the key as written says what it measured, which
    a persisted cache a human may have to read is better for.

    The hash COUNT is part of the key because it is part of the workload: a
    salted mode tries each candidate against every distinct hash, so the count
    changes both the keyspace and the rate at which the GPU walks it. ``h?``
    when the count is unknown, which keeps an unknown-count entry from ever
    being served as though it described a known one.
    """
    base = os.path.basename(str(wordlist or "")).strip() or "unknown"
    rule = os.path.basename(str(rule_path or "")).strip() or "none"
    try:
        count = int(hash_count) if hash_count else 0
    except (TypeError, ValueError):
        count = 0
    suffix = f"h{count}" if count > 0 else "h?"
    return f"{base}+{rule}+{suffix}"


def mode_is_salted(mode: str) -> bool:
    """Whether hashcat treats ``mode`` as a salted hash.

    A salted mode multiplies the keyspace by the number of distinct hashes
    loaded: hashcat has to try every candidate against every salt. An unlisted
    mode answers ``True``, the direction that over-quotes rather than
    under-quotes.
    """
    return _MODE_IS_SALTED.get(str(mode or "").strip(), True)


def known_salted_modes() -> dict[str, bool]:
    """The declared mode-to-salted map, for the drift test that re-reads hashcat."""
    return dict(_MODE_IS_SALTED)


def parse_status_tick(line: str) -> Optional[dict]:
    """Parse one hashcat ``--status-json`` line into ``{speed, status, keyspace}``.

    ``speed`` is the sum over every reported backend device, in hashes per
    second of KEYSPACE position, which is the unit the ``progress`` pair counts
    in. Returns ``None`` for any line that is not a parseable status object
    carrying device speeds. Never raises.
    """
    text = str(line or "").strip()
    if not text or text[0] != "{" or '"devices"' not in text:
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    devices = data.get("devices")
    if not isinstance(devices, (list, tuple)):
        return None
    speed = 0.0
    for device in devices:
        if not isinstance(device, dict):
            continue
        try:
            speed += float(device.get("speed") or 0)
        except (TypeError, ValueError):
            continue
    if speed <= 0:
        return None
    keyspace: Optional[int] = None
    progress = data.get("progress")
    if isinstance(progress, (list, tuple)) and len(progress) == 2:
        try:
            keyspace = int(progress[1])
        except (TypeError, ValueError):
            keyspace = None
    status = data.get("status")
    return {
        "speed": speed,
        "status": int(status) if isinstance(status, int) else None,
        "keyspace": keyspace,
    }


def rate_from_status_stream(output: str) -> Optional[float]:
    """The achieved rate in H/s from a probe's captured ``--status-json`` stream.

    Takes the LOWEST of the running ticks, not their median, and the choice is
    deliberate on two counts.

    The within-run trend is monotonic rather than noisy: a GPU coming off idle
    starts at its boost clock and settles down, measured at 332 MH/s falling to
    259 over thirty seconds on one mode. Against a declining series the lowest
    tick IS the sustained rate, which is the rate a crack running for minutes
    will actually hold, while a median of the same series reports a speed that
    existed for the first few seconds only.

    And where the series is genuinely noisy rather than declining, the lowest
    tick biases the estimate LONG. That is the safe direction for this number:
    the defect being fixed here is an estimate that promised speed the hardware
    could not deliver, so erring toward a longer quote is a smaller error than
    erring toward a shorter one.

    Falls back to every tick carrying a positive speed, which is what a run that
    exhausted its keyspace inside the probe window leaves behind. ``None`` when
    the stream carried no usable tick at all.
    """
    running: list[float] = []
    any_tick: list[float] = []
    for line in (output or "").splitlines():
        tick = parse_status_tick(line)
        if tick is None:
            continue
        any_tick.append(tick["speed"])
        if tick["status"] == _STATUS_RUNNING:
            running.append(tick["speed"])
    pool = running or any_tick
    if not pool:
        return None
    return min(pool)


def _hashcat_example_hash_info(
    command_executor: Callable[..., Any], mode: str
) -> Optional[dict]:
    """hashcat's own ``--example-hashes`` record for ``mode``, or ``None``.

    The output carries a banner line ahead of the JSON object, so the object is
    located rather than assumed to start at byte zero.

    Runs under a unique ``--session`` even though it touches no device: hashcat
    takes its single-instance lock on the session NAME, so a hash-info lookup on
    the default name fails outright while any other hashcat is alive, including
    the operator's own running crack. With its own name it answers regardless.
    """
    from adscan_internal.cli.tools_env import (  # noqa: PLC0415
        maybe_wrap_hashcat_for_container,
    )
    from adscan_internal.services.hashcat_coordination import (  # noqa: PLC0415
        unique_crack_session_name,
    )

    argv = [
        "hashcat",
        "-m",
        str(mode),
        "--session",
        unique_crack_session_name("adscan-hash-info"),
        "--example-hashes",
        "--machine-readable",
    ]
    cmd = " ".join(shlex.quote(a) for a in argv)
    try:
        result = command_executor(
            maybe_wrap_hashcat_for_container(cmd), timeout=60, untrusted_output=True
        )
    except Exception as exc:  # noqa: BLE001 -- an optional probe degrades honestly
        telemetry.capture_exception(exc)
        print_warning_debug(f"achieved-rate: example-hash lookup failed: {exc}")
        return None
    if result is None:
        return None
    text = (
        f"{getattr(result, 'stdout', '') or ''}\n{getattr(result, 'stderr', '') or ''}"
    )
    start = text.find("{")
    if start < 0:
        return None
    try:
        data = json.loads(text[start:])
    except (ValueError, TypeError):
        return None
    record = (data or {}).get(str(mode))
    return record if isinstance(record, dict) else None


def uncrackable_variant(example_hash: str) -> Optional[str]:
    """Mutate ``example_hash``'s digest so no candidate password can match it.

    Rewrites the LAST run of 16 or more hex characters, which is the digest or
    ciphertext field in every mode ADscan cracks. Only hex characters change,
    and the field keeps its length, so the mode's parser still accepts the line
    while the value it has to reproduce no longer corresponds to any password.
    Returns ``None`` when the hash carries no such field, which is the signal to
    skip the probe rather than feed hashcat something it will reject.
    """
    text = str(example_hash or "").strip()
    if not text:
        return None
    runs = list(_HEX_RUN_RE.finditer(text))
    if not runs:
        return None
    last = runs[-1]
    segment = last.group(0)
    flipped = "".join("f" if c.lower() != "f" else "0" for c in segment[:16])
    return text[: last.start()] + flipped + segment[16:] + text[last.end() :]


def _write_probe_hashfile(
    command_executor: Callable[..., Any], mode: str, path: str
) -> bool:
    """Materialise a one-line, uncrackable probe hashfile for ``mode``.

    Routed through the canonical ``write_crack_hashfile`` so the line is shaped
    exactly as a real crack's input is, including the per-mode ``--username``
    prepend. Returns whether a line was written.
    """
    from adscan_internal.cli.cracking import write_crack_hashfile  # noqa: PLC0415

    info = _hashcat_example_hash_info(command_executor, mode)
    if not info:
        return False
    synthetic = uncrackable_variant(str(info.get("example_hash") or ""))
    if not synthetic:
        return False
    try:
        written = write_crack_hashfile(path, [("probe", synthetic)], mode=str(mode))
    except Exception as exc:  # noqa: BLE001 -- an optional probe degrades honestly
        telemetry.capture_exception(exc)
        print_warning_debug(f"achieved-rate: probe hashfile not written: {exc}")
        return False
    return written > 0


def build_probe_argv(
    mode: str,
    *,
    hash_file: str,
    wordlist: str,
    rule_path: Optional[str],
    session: str,
    device_args: "list[str]",
    runtime_seconds: int = PROBE_RUNTIME_SECONDS,
    status_timer_seconds: int = PROBE_STATUS_TIMER_SECONDS,
    disable_potfile: bool = True,
) -> "list[str]":
    """The probe's hashcat argv, mirroring the production crack's shape.

    Same ``-m <mode> --username --session ... --status --status-json
    --status-timer N [-D 2] --runtime=N [-r rules] <hashfile> <wordlist>``
    the crack runner builds, plus the short ``--runtime`` that bounds the probe.

    ``disable_potfile`` adds ``--potfile-disable``, and is for the SYNTHETIC
    target only: a hash that cannot crack has nothing to record, so keeping the
    potfile out of it is tidier. It must be ``False`` for a probe running the
    operator's REAL hash file, where a password recovered inside the probe
    window has to survive into the crack that follows rather than being thrown
    away.

    There is deliberately no ``-O``, no ``-w`` and no mask: the measurement is
    worth having only if it measures the configuration the crack will run in.
    """
    argv = [
        "hashcat",
        "-m",
        str(mode),
        "--username",
        "--session",
        session,
        "--status",
        "--status-json",
        "--status-timer",
        str(int(status_timer_seconds)),
        *(["--potfile-disable"] if disable_potfile else []),
        *device_args,
        f"--runtime={int(runtime_seconds)}",
    ]
    if rule_path:
        argv += ["-r", rule_path]
    argv += [hash_file, wordlist]
    return argv


def run_achieved_rate_probe(
    command_executor: Callable[..., Any],
    *,
    mode: str,
    wordlist: str,
    rule_path: Optional[str],
    hash_file: Optional[str] = None,
    device_args: Optional["list[str]"] = None,
    scratch_dir: Optional[str] = None,
    runtime_seconds: int = PROBE_RUNTIME_SECONDS,
) -> Optional[float]:
    """Measure the rate a real crack achieves for one workload on this box.

    Args:
        command_executor: ``shell.run_command``-shaped callable.
        mode: hashcat mode string.
        wordlist: The base wordlist the crack will actually use.
        rule_path: The rule file the crack will actually use, or ``None`` for a
            ruleless rung.
        hash_file: The hash file the crack will actually run. Supplying it is
            what makes the measurement right for a SALTED mode, because the
            number of distinct hashes changes the rate as much as the rule
            count does. The potfile stays enabled for this case, so a password
            recovered inside the probe window reaches the crack that follows.
            Omitted, a single uncrackable synthetic target is written instead.
        device_args: Device selection, e.g. ``["-D", "2"]``. Passed through so
            the probe measures on the devices the crack will run on.
        scratch_dir: Where a synthetic probe hashfile is written. Defaults to
            the PAL scratch dir. Unused when ``hash_file`` is supplied.
        runtime_seconds: The probe's own budget.

    Returns:
        Achieved H/s of keyspace position, or ``None`` when nothing could be
        measured. ``None`` is the honest answer and every caller degrades to a
        provisional estimate rather than treating a benchmark number as measured.
    """
    from adscan_internal.cli.tools_env import (  # noqa: PLC0415
        maybe_wrap_hashcat_for_container,
    )
    from adscan_internal.services.hashcat_coordination import (  # noqa: PLC0415
        hashcat_slot,
        unique_crack_session_name,
    )

    if not wordlist or not os.path.isfile(wordlist):
        print_info_debug(
            f"achieved-rate: base wordlist absent, no probe for mode {mode}"
        )
        return None
    if rule_path and not os.path.isfile(rule_path):
        print_info_debug(f"achieved-rate: rule file absent, no probe for mode {mode}")
        return None

    # Only a file this function CREATED is removed afterwards. The operator's
    # real hash file is the caller's.
    synthetic_path: Optional[str] = None
    try:
        session = unique_crack_session_name("adscan-rate-probe")
        if hash_file and os.path.isfile(hash_file):
            target = hash_file
            disable_potfile = False
        else:
            if scratch_dir:
                base_dir = scratch_dir
            else:
                from adscan_core.pal.paths import (  # noqa: PLC0415
                    scratch_dir as pal_scratch,
                )

                base_dir = str(pal_scratch())
            os.makedirs(base_dir, exist_ok=True)
            synthetic_path = os.path.join(base_dir, f"{session}.hash")
            if not _write_probe_hashfile(command_executor, mode, synthetic_path):
                return None
            target = synthetic_path
            disable_potfile = True
        argv = build_probe_argv(
            mode,
            hash_file=target,
            wordlist=wordlist,
            rule_path=rule_path,
            session=session,
            device_args=list(device_args or []),
            runtime_seconds=runtime_seconds,
            disable_potfile=disable_potfile,
        )
        cmd = " ".join(shlex.quote(str(a)) for a in argv)
        # Serialized against every other hashcat launch through the shared
        # single-instance slot, non-blocking: a real crack wanting the GPU must
        # never wait behind a measurement it did not ask for. The slot spans
        # PROCESSES, so this also declines while another ADscan session is
        # cracking, which is the case this probe used to measure through and
        # report as though the hardware had been quiet. Declining leaves the
        # estimate on its provisional calibration, flagged as provisional:
        # one fewer measurement, rather than a number that misquotes the GPU.
        with hashcat_slot(block=False) as slot:
            if not slot:
                print_info_debug(
                    f"achieved-rate: the GPU is busy with a crack, no probe for "
                    f"mode {mode} (the estimate stays provisional)"
                )
                return None
            result = command_executor(
                maybe_wrap_hashcat_for_container(cmd),
                # Above the probe's own --runtime, never racing it: hashcat
                # stops itself and this only bounds a hashcat that outlives its
                # own limit.
                timeout=int(runtime_seconds) + 120,
                untrusted_output=True,
            )
        if result is None:
            return None
        output = (
            f"{getattr(result, 'stdout', '') or ''}\n"
            f"{getattr(result, 'stderr', '') or ''}"
        )
        rate = rate_from_status_stream(output)
        if rate:
            print_info_debug(
                f"achieved-rate: mode {mode} rules="
                f"{os.path.basename(rule_path) if rule_path else 'none'} "
                f"measured {rate / 1e9:.4f} GH/s"
            )
        return rate
    except Exception as exc:  # noqa: BLE001 -- an optional probe degrades honestly
        telemetry.capture_exception(exc)
        print_warning_debug(f"achieved-rate: probe failed for mode {mode}: {exc}")
        return None
    finally:
        try:
            if synthetic_path:
                for suffix in ("", ".show"):
                    candidate = synthetic_path + suffix
                    if os.path.isfile(candidate):
                        os.unlink(candidate)
        except OSError:
            pass


__all__ = [
    "PROBE_RUNTIME_SECONDS",
    "achieved_rate_key",
    "PROBE_STATUS_TIMER_SECONDS",
    "build_probe_argv",
    "known_salted_modes",
    "mode_is_salted",
    "parse_status_tick",
    "rate_from_status_stream",
    "run_achieved_rate_probe",
    "uncrackable_variant",
]
